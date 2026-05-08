import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import hashlib
from pathlib import Path
from urllib.parse import urlparse

import chromadb
import tldextract
from sentence_transformers import SentenceTransformer


# ════════════════════════════════════════════════════════════════
# PATHS
# ════════════════════════════════════════════════════════════════

URLHAUS_FILE = Path("data/feeds/urlhaus.txt")
CHROMA_PATH = "data/chromadb"


# ════════════════════════════════════════════════════════════════
# CHROMADB
# ════════════════════════════════════════════════════════════════

client = chromadb.PersistentClient(path=CHROMA_PATH)

collection = client.get_or_create_collection(
    name="urlhaus"
)

encoder = SentenceTransformer(
    "sentence-transformers/all-MiniLM-L6-v2"
)


# ════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════

def normalize_url(url: str) -> str:
    parsed = urlparse(url.lower().strip())
    domain = parsed.netloc.replace("www.", "")
    path = parsed.path or "/"
    return f"{domain}{path}"


def make_id(url: str):
    return hashlib.md5(url.encode()).hexdigest()


# ════════════════════════════════════════════════════════════════
# DATABASE BUILD
# ════════════════════════════════════════════════════════════════

def build_database():

    if not URLHAUS_FILE.exists():
        raise FileNotFoundError("Missing data/feeds/urlhaus.txt")

    imported = 0

    print("Building ChromaDB from URLHaus...")

    with open(URLHAUS_FILE, encoding="utf-8", errors="ignore") as f:

        for line in f:

            line = line.strip()

            if not line or line.startswith("#") or not line.startswith("http"):
                continue

            try:
                normalized = normalize_url(line)

                embedding = encoder.encode(normalized).tolist()

                collection.add(
                    ids=[make_id(normalized)],
                    documents=[normalized],
                    embeddings=[embedding],
                    metadatas=[{"source": "urlhaus"}]
                )

                imported += 1

                if imported % 1000 == 0:
                    print(f"Imported {imported}")

            except Exception:
                pass

    print(f"\n✅ DONE — {imported} URLs imported")


# ════════════════════════════════════════════════════════════════
# SIMILARITY
# ════════════════════════════════════════════════════════════════

def similarity_score(url: str):

    normalized = normalize_url(url)
    embedding = encoder.encode(normalized).tolist()

    results = collection.query(
        query_embeddings=[embedding],
        n_results=3
    )

    distances = results.get("distances", [[]])[0]

    if not distances:
        return 0.0

    best = min(distances)

    similarity = 1.0 - (best / 2)

    return max(0.0, min(similarity, 1.0))


# ════════════════════════════════════════════════════════════════
# CLASSIFIER
# ════════════════════════════════════════════════════════════════

def classify_url(url: str):

    similarity = similarity_score(url)
    normalized = normalize_url(url)

    heuristic = 0.0

    # ─────────────────────────────────────────
    # 1. Suspicious keyword detection
    # ─────────────────────────────────────────
    suspicious_words = [
        "login", "secure", "verify", "wallet",
        "signin", "auth", "update", "account",
    ]

    for word in suspicious_words:
        if word in normalized:
            heuristic += 0.08

    # ─────────────────────────────────────────
    # 2. Domain structure risk
    # ─────────────────────────────────────────
    extracted = tldextract.extract(normalized)
    domain = f"{extracted.domain}.{extracted.suffix}"

    if len(domain.split(".")) >= 3:
        heuristic += 0.15

    # ─────────────────────────────────────────
    # 3. HTTPS SIGNAL (FIXED & IMPROVED)
    # ─────────────────────────────────────────
    if url.startswith("https"):
        https_bonus = -0.05   # safer → reduce risk
    else:
        https_bonus = 0.20    # unsafe → increase risk

    heuristic += https_bonus

    # ─────────────────────────────────────────
    # 4. FINAL SCORE (rebalance)
    # ─────────────────────────────────────────
    final_score = (
        similarity * 0.60 +
        heuristic * 0.40
    )

    final_score = round(min(final_score, 1.0), 4)

    # ─────────────────────────────────────────
    # 5. VERDICT
    # ─────────────────────────────────────────
    if final_score >= 0.80:
        verdict = "MALICIOUS"
    elif final_score >= 0.50:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "url": url,
        "domain": domain,
        "similarity": round(similarity, 4),
        "heuristic": round(heuristic, 4),
        "score_final": final_score,
        "verdict": verdict,
    }


# ════════════════════════════════════════════════════════════════
# TEST
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    build_database()

    tests = [
        "http://paypal-secure-login.com",
        "https://paypal-secure-login.com",
        "https://google.com",
        "http://amazon-auth-update.net",
    ]

    for url in tests:
        print("\n════════════════════════════")
        print(classify_url(url))