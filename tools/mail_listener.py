"""
tools/mail_listener.py — Étape 1 & 2 : Capture IMAP + Dispatch orchestrateur
Écoute la boîte IMAP toutes les N secondes, parse chaque mail,
et dispatche vers l'orchestrateur pour analyse complète.
"""

import asyncio
import email
import imaplib
import logging
import quopri
import re
import time
from base64 import b64decode
from dataclasses import dataclass, field
from email import policy
from email.header import decode_header
from email.message import Message
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("mail_listener")


# ══════════════════════════════════════════════════════════════════════════════
#  Modèles de données (EmailPayload)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes
    size_bytes: int


@dataclass
class EmailPayload:
    uid: str
    message_id: str
    sender: str
    recipients: list[str]
    subject: str
    body_text: str
    body_html: str
    headers: dict
    attachments: list[Attachment] = field(default_factory=list)
    received_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """Sérialise le payload pour l'orchestrateur (sans les bytes bruts)."""
        return {
            "uid": self.uid,
            "message_id": self.message_id,
            "sender": self.sender,
            "recipients": self.recipients,
            "subject": self.subject,
            "body": self.body_text or self.body_html or "",
            "headers": self.headers,
            "attachments": [
                {
                    "filename": a.filename,
                    "content_type": a.content_type,
                    "data": a.data,
                    "size_bytes": a.size_bytes,
                }
                for a in self.attachments
            ],
            "received_at": self.received_at,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  Décodage des en-têtes RFC 2047
# ══════════════════════════════════════════════════════════════════════════════

def decode_mime_words(raw: str) -> str:
    """Décode les mots encodés RFC 2047 (=?utf-8?B?...?= etc.)."""
    if not raw:
        return ""
    parts = decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except (LookupError, UnicodeDecodeError):
                decoded.append(part.decode("latin-1", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


# ══════════════════════════════════════════════════════════════════════════════
#  Parser de message email → EmailPayload
# ══════════════════════════════════════════════════════════════════════════════

def parse_email_message(raw_bytes: bytes, uid: str) -> EmailPayload:
    """
    Transforme les bytes bruts d'un message IMAP en EmailPayload structuré.
    Extrait : headers, corps texte/HTML, pièces jointes.
    """
    msg: Message = email.message_from_bytes(raw_bytes, policy=policy.compat32)

    # ── Headers ──────────────────────────────────────────────────────────────
    subject = decode_mime_words(msg.get("Subject", ""))
    sender = decode_mime_words(msg.get("From", ""))
    message_id = msg.get("Message-ID", f"<generated-{uid}>").strip()

    # Extraire l'adresse email brute depuis "Nom <email@ex.com>"
    sender_match = re.search(r"<([^>]+)>", sender)
    sender_email = sender_match.group(1).lower() if sender_match else sender.lower().strip()

    # Destinataires
    recipients_raw = msg.get("To", "") + "," + msg.get("Cc", "")
    recipients = [
        r.strip().lower()
        for r in re.findall(r"[\w.+-]+@[\w.-]+\.\w+", recipients_raw)
    ]

    # Tous les headers bruts (utile pour l'analyse SPF/DKIM)
    headers = {k: decode_mime_words(v) for k, v in msg.items()}

    # ── Corps du message ──────────────────────────────────────────────────────
    body_text = ""
    body_html = ""
    attachments: list[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            # Pièce jointe
            if "attachment" in disposition or part.get_filename():
                filename = decode_mime_words(part.get_filename() or "unknown")
                data = _decode_part_payload(part)
                attachments.append(Attachment(
                    filename=filename,
                    content_type=ct,
                    data=data,
                    size_bytes=len(data),
                ))
            elif ct == "text/plain" and not body_text:
                body_text = _decode_text_part(part)
            elif ct == "text/html" and not body_html:
                body_html = _decode_text_part(part)
            elif "image" in ct:
                # Images inline — potentiel QR code
                data = _decode_part_payload(part)
                if data:
                    filename = decode_mime_words(part.get_filename() or f"inline_{ct.replace('/','-')}")
                    attachments.append(Attachment(
                        filename=filename,
                        content_type=ct,
                        data=data,
                        size_bytes=len(data),
                    ))
    else:
        ct = msg.get_content_type()
        if ct == "text/plain":
            body_text = _decode_text_part(msg)
        elif ct == "text/html":
            body_html = _decode_text_part(msg)

    return EmailPayload(
        uid=uid,
        message_id=message_id,
        sender=sender_email,
        recipients=recipients,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        headers=headers,
        attachments=attachments,
    )


def _decode_text_part(part: Message) -> str:
    """Décode le contenu texte d'une partie de message."""
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("latin-1", errors="replace")


def _decode_part_payload(part: Message) -> bytes:
    """Récupère les bytes bruts d'une pièce jointe."""
    payload = part.get_payload(decode=True)
    return payload if isinstance(payload, bytes) else b""


# ══════════════════════════════════════════════════════════════════════════════
#  Connexion IMAP
# ══════════════════════════════════════════════════════════════════════════════

class IMAPConnection:
    """Gère la connexion IMAP SSL avec reconnexion automatique."""

    def __init__(self, host: str, port: int, user: str, password: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self._conn: Optional[imaplib.IMAP4_SSL] = None

    def connect(self) -> bool:
        """Établit la connexion IMAP SSL."""
        try:
            self._conn = imaplib.IMAP4_SSL(self.host, self.port)
            self._conn.login(self.user, self.password)
            logger.info(f"✅ Connecté à {self.host} en tant que {self.user}")
            return True
        except imaplib.IMAP4.error as e:
            logger.error(f"❌ Échec connexion IMAP {self.host}: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Erreur inattendue IMAP: {e}")
            return False

    def disconnect(self):
        if self._conn:
            try:
                self._conn.logout()
            except Exception:
                pass
            self._conn = None

    def fetch_unread_uids(self, folder: str = "INBOX") -> list[str]:
        """Retourne les UIDs des messages non lus dans le dossier."""
        try:
            self._conn.select(folder, readonly=False)
            _, data = self._conn.search(None, "UNSEEN")
            if data[0]:
                return data[0].decode().split()
            return []
        except imaplib.IMAP4.abort:
            logger.warning("Connexion IMAP interrompue — reconnexion...")
            self.connect()
            return []
        except Exception as e:
            logger.error(f"Erreur fetch UIDs: {e}")
            return []

    def fetch_message_bytes(self, uid: str) -> Optional[bytes]:
        """Récupère les bytes bruts d'un message par son UID."""
        try:
            _, data = self._conn.fetch(uid, "(RFC822)")
            if data and data[0]:
                return data[0][1] if isinstance(data[0], tuple) else None
            return None
        except Exception as e:
            logger.error(f"Erreur fetch message UID={uid}: {e}")
            return None

    def mark_as_seen(self, uid: str):
        """Marque le message comme lu."""
        try:
            self._conn.store(uid, "+FLAGS", "\\Seen")
        except Exception as e:
            logger.warning(f"Impossible de marquer UID={uid} comme lu: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  Listener principal — Étape 1 & 2
# ══════════════════════════════════════════════════════════════════════════════

class MailListener:
    """
    Étape 1 : Écoute IMAP en boucle (polling toutes les N secondes).
    Étape 2 : Parse chaque email et dispatche vers l'orchestrateur.
    """

    def __init__(self, orchestrator_callback=None):
        """
        Args:
            orchestrator_callback: fonction async appelée avec chaque EmailPayload.
                                   Si None, affiche juste les infos du mail (mode démo).
        """
        from config.settings import Settings
        cfg = Settings()

        self.imap = IMAPConnection(
            host=cfg.IMAP_HOST,
            port=cfg.IMAP_PORT,
            user=cfg.IMAP_USER,
            password=cfg.IMAP_PASSWORD,
        )
        self.poll_interval = cfg.POLL_INTERVAL
        self.orchestrator_callback = orchestrator_callback
        self._running = False
        self._processed_uids: set[str] = set()  # Anti-doublon session

    async def start(self):
        """Lance la boucle de polling IMAP."""
        logger.info(f"🚀 MailListener démarré — poll toutes les {self.poll_interval}s")

        if not self.imap.connect():
            logger.error("Impossible de démarrer : échec connexion IMAP")
            return

        self._running = True
        try:
            while self._running:
                await self._poll_once()
                await asyncio.sleep(self.poll_interval)
        except asyncio.CancelledError:
            logger.info("MailListener arrêté (CancelledError)")
        finally:
            self.imap.disconnect()
            logger.info("Connexion IMAP fermée")

    def stop(self):
        self._running = False

    async def _poll_once(self):
        """Un cycle de polling : récupère et traite tous les nouveaux mails."""
        uids = self.imap.fetch_unread_uids()
        if not uids:
            logger.debug("Aucun nouveau message")
            return

        logger.info(f"📬 {len(uids)} nouveaux message(s) trouvé(s)")

        for uid in uids:
            if uid in self._processed_uids:
                continue

            raw = self.imap.fetch_message_bytes(uid)
            if not raw:
                logger.warning(f"Impossible de récupérer le message UID={uid}")
                continue

            try:
                payload = parse_email_message(raw, uid)
                self._processed_uids.add(uid)
                self.imap.mark_as_seen(uid)

                logger.info(
                    f"📨 UID={uid} | De: {payload.sender} | "
                    f"Sujet: {payload.subject[:60]} | "
                    f"PJ: {len(payload.attachments)}"
                )

                # Étape 2 : Dispatch vers l'orchestrateur
                if self.orchestrator_callback:
                    await self.orchestrator_callback(payload)
                else:
                    # Mode démo : afficher les infos
                    _demo_display(payload)

            except Exception as e:
                logger.error(f"Erreur parsing UID={uid}: {e}", exc_info=True)


def _demo_display(payload: EmailPayload):
    """Affiche les informations du mail parsé (mode démo sans orchestrateur)."""
    print("\n" + "═" * 60)
    print(f"  UID         : {payload.uid}")
    print(f"  Message-ID  : {payload.message_id}")
    print(f"  Expéditeur  : {payload.sender}")
    print(f"  Destinataires : {', '.join(payload.recipients[:3])}")
    print(f"  Sujet       : {payload.subject}")
    print(f"  Corps texte : {len(payload.body_text)} chars")
    print(f"  Corps HTML  : {len(payload.body_html)} chars")
    print(f"  PJ          : {len(payload.attachments)}")
    for att in payload.attachments:
        print(f"    └─ {att.filename} ({att.content_type}, {att.size_bytes} bytes)")
    print("═" * 60 + "\n")


# ══════════════════════════════════════════════════════════════════════════════
#  Point d'entrée — Mode standalone (test sans orchestrateur)
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import os
    from dotenv import load_dotenv
    load_dotenv()

    print("🔍 Ghost Sentry — MailListener (mode démo)")
    print("   Connexion IMAP et affichage des mails entrants...")
    print("   Ctrl+C pour arrêter\n")

    listener = MailListener(orchestrator_callback=None)

    try:
        asyncio.run(listener.start())
    except KeyboardInterrupt:
        print("\n👋 Arrêt propre du listener")
