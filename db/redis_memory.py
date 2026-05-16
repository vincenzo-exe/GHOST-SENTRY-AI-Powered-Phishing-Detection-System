"""
db/redis_memory.py — Historique des expéditeurs sur 30 jours (Redis)
"""

import json
import logging
from datetime import datetime

logger = logging.getLogger("redis_memory")


class RedisMemory:
    """
    Stocke l'historique des scores par expéditeur.
    Clé : sender_history:<email>
    TTL : 30 jours
    """

    def __init__(self):
        import redis
        from config.settings import Settings

        cfg = Settings()
        self.client = redis.Redis(
            host=cfg.REDIS_HOST,
            port=cfg.REDIS_PORT,
            db=cfg.REDIS_DB,
            decode_responses=True,
        )
        self.ttl = cfg.REDIS_TTL_DAYS * 86400  # secondes
        logger.info("Redis initialisé")

    def update_sender_history(self, sender: str, score: float):
        """Ajoute une entrée dans l'historique de l'expéditeur."""
        key = f"sender_history:{sender}"
        entry = json.dumps({"score": score, "at": datetime.utcnow().isoformat()})
        try:
            pipe = self.client.pipeline()
            pipe.rpush(key, entry)
            pipe.ltrim(key, -100, -1)  # Garde les 100 derniers
            pipe.expire(key, self.ttl)
            pipe.execute()
        except Exception as e:
            logger.error(f"Erreur Redis update : {e}")

    def get_sender_risk(self, sender: str) -> dict:
        """
        Calcule le score de risque historique d'un expéditeur.
        Retourne : {'avg_score': float, 'count': int, 'max_score': float}
        """
        key = f"sender_history:{sender}"
        try:
            entries = self.client.lrange(key, 0, -1)
            if not entries:
                return {"avg_score": 0.0, "count": 0, "max_score": 0.0, "known": False}

            scores = [json.loads(e)["score"] for e in entries]
            return {
                "avg_score": round(sum(scores) / len(scores), 3),
                "max_score": round(max(scores), 3),
                "count": len(scores),
                "known": True,
            }
        except Exception as e:
            logger.error(f"Erreur Redis get : {e}")
            return {"avg_score": 0.0, "count": 0, "max_score": 0.0, "known": False}

    def is_whitelisted(self, sender: str) -> bool:
        """Vérifie si l'expéditeur est dans la whitelist."""
        return self.client.sismember("whitelist", sender)

    def add_to_whitelist(self, sender: str):
        self.client.sadd("whitelist", sender)
        logger.info(f"Whitelist : {sender} ajouté")

    def add_to_blacklist(self, sender: str):
        self.client.sadd("blacklist", sender)
        logger.info(f"Blacklist : {sender} ajouté")

    def is_blacklisted(self, sender: str) -> bool:
        return self.client.sismember("blacklist", sender)
