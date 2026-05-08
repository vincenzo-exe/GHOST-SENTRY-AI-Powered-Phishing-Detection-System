"""
tools/text_pipeline.py — Analyse du contenu textuel et pièces jointes
Modules : homoglyph · attachment · memory (historique expéditeur)
"""

import asyncio
import logging
import re
from typing import Optional

logger = logging.getLogger("text_pipeline")


# ══════════════════════════════════════════════════════════════════════════════
#  Homoglyph detector
# ══════════════════════════════════════════════════════════════════════════════

# Mapping caractères Unicode trompeurs → ASCII équivalent
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",  # cyrillique
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g",
    "ⅼ": "l", "ⅰ": "i", "ⅴ": "v", "ⅹ": "x",           # chiffres romains
    "０": "0", "１": "1", "２": "2", "３": "3",           # pleine largeur
}

# Mots sensibles à surveiller pour homoglyphes
SENSITIVE_WORDS = [
    "paypal", "amazon", "apple", "microsoft", "google",
    "netflix", "facebook", "instagram", "bank", "secure",
    "account", "verify", "update", "login", "password",
]


def detect_homoglyphs(text: str) -> dict:
    """
    Cherche des mots qui ressemblent à des mots sensibles via homoglyphes.
    Retourne : {'found': bool, 'matches': list, 'score': float}
    """
    normalized = "".join(HOMOGLYPH_MAP.get(c, c) for c in text.lower())
    matches = []

    for word in SENSITIVE_WORDS:
        if word in normalized and word not in text.lower():
            # Le mot apparaît dans la version normalisée mais pas dans l'original
            matches.append(word)

    score = min(len(matches) * 0.25, 1.0)
    return {"found": bool(matches), "matches": matches, "score": score}


# ══════════════════════════════════════════════════════════════════════════════
#  Attachment analyzer
# ══════════════════════════════════════════════════════════════════════════════

DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".com", ".hta", ".wsf", ".msi",
}

SUSPICIOUS_MIME = {
    "application/x-msdownload",
    "application/x-executable",
    "application/javascript",
    "application/x-bat",
}


def analyze_attachment(attachment: dict) -> dict:
    """
    Analyse une pièce jointe : extension, MIME type, macros VBA, JS dans PDF.
    Retourne : {'risk': str, 'score': float, 'reason': str}
    """
    filename = attachment.get("filename", "") or ""
    content_type = attachment.get("content_type", "") or ""
    data = attachment.get("data", b"") or b""

    score = 0.0
    reasons = []

    # Extension dangereuse
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in DANGEROUS_EXTENSIONS:
        score += 0.5
        reasons.append(f"extension dangereuse : {ext}")

    # MIME suspect
    if content_type in SUSPICIOUS_MIME:
        score += 0.3
        reasons.append(f"MIME suspect : {content_type}")

    # Double extension (rapport.pdf.exe)
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        score += 0.3
        reasons.append("double extension détectée")

    # Macro VBA dans Office (signature OLE : D0 CF 11 E0)
    if data[:4] == b"\xd0\xcf\x11\xe0":
        score += 0.4
        reasons.append("fichier OLE/macro VBA détecté")

    # JavaScript dans PDF (%PDF header + /JS keyword)
    if data[:4] == b"%PDF" and b"/JS" in data[:4096]:
        score += 0.4
        reasons.append("JavaScript embarqué dans PDF")

    score = min(score, 1.0)
    risk = "HIGH" if score >= 0.6 else "MEDIUM" if score >= 0.3 else "LOW"

    return {
        "filename": filename,
        "risk": risk,
        "score": round(score, 3),
        "reason": " | ".join(reasons) if reasons else "OK",
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Urgent language detector
# ══════════════════════════════════════════════════════════════════════════════

URGENT_PATTERNS = [
    r"\bimmédiat\b", r"\burgent\b", r"\baction required\b",
    r"\bverify.{0,20}account\b", r"\bsuspended\b", r"\bblocked\b",
    r"\bclick here\b", r"\bconfirm.{0,20}identity\b",
    r"\b24.?hours?\b", r"\bexpir", r"\blimited time\b",
]


def detect_urgent_language(text: str) -> float:
    """Détecte le langage d'urgence typique du phishing. Score 0–1."""
    text_lower = text.lower()
    hits = sum(1 for p in URGENT_PATTERNS if re.search(p, text_lower))
    return round(min(hits * 0.15, 1.0), 3)


# ══════════════════════════════════════════════════════════════════════════════
#  TextPipeline principal
# ══════════════════════════════════════════════════════════════════════════════

class TextPipeline:
    """
    Agrège les analyses texte :
    - homoglyphes dans sujet + corps
    - pièces jointes
    - langage urgent
    Retourne un score global 0–1
    """

    async def analyze(self, mail: dict) -> float:
        full_text = f"{mail.get('subject', '')} {mail.get('body', '')}"

        # Analyses en parallèle (CPU-bound → to_thread)
        homoglyph_result, urgency_score = await asyncio.gather(
            asyncio.to_thread(detect_homoglyphs, full_text),
            asyncio.to_thread(detect_urgent_language, full_text),
        )

        # Pièces jointes
        attachment_scores = []
        for att in mail.get("attachments", []):
            result = analyze_attachment(att)
            attachment_scores.append(result["score"])
            if result["risk"] == "HIGH":
                logger.warning(
                    f"PJ dangereuse uid={mail['uid']} : {result['reason']}"
                )

        att_score = max(attachment_scores) if attachment_scores else 0.0

        # Agrégation
        score = (
            0.30 * homoglyph_result["score"]
            + 0.35 * urgency_score
            + 0.35 * att_score
        )

        logger.debug(
            f"TextPipeline uid={mail['uid']} "
            f"homoglyph={homoglyph_result['score']} "
            f"urgency={urgency_score} att={att_score} → {score:.3f}"
        )

        return round(min(score, 1.0), 4)
