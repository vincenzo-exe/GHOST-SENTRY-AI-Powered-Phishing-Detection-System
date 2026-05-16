import warnings
import logging
import asyncio
import os

# ============================================
# DÉSACTIVATION COMPLÈTE DES WARNINGS
# ============================================
warnings.filterwarnings("ignore")
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["TRANSFORMERS_VERBOSITY"] = "error"

logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("chromadb").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("filelock").setLevel(logging.ERROR)

print("🔥 Chargement des modèles en mémoire...\n")

# Imports
from tools.text_pipeline import TextPipeline
from tools.url_pipeline import URLPipeline
from tools.chroma_rag import ChromaRAG

try:
    from models.distilbert_classifier import DistilBERTClassifier as BERTClass
except ImportError:
    try:
        from models.distilbert_classifier import distilbert_classifier as BERTClass
    except ImportError:
        from models.distilbert_classifier import DistilBertClassifier as BERTClass

async def warmup():
    print("📝 Initialisation Text Pipeline...")
    text = TextPipeline()
    
    print("🔗 Initialisation URL Pipeline...")
    url = URLPipeline()
    
    print("🧠 Initialisation ChromaDB RAG (11,000 URLs)...")
    rag = ChromaRAG()
    
    print("🤖 Initialisation BERT Classifier...")
    try:
        bert = BERTClass()
        print("   ✅ BERT chargé")
    except Exception as e:
        print(f"   ⚠️  BERT non disponible: {e}")
        bert = None
    
    dummy = {
        "uid": "warmup_001",
        "from": "warmup@test.com",
        "subject": "Warmup test",
        "body_text": "Ceci est un email de préchauffage.",
        "urls": [],
        "attachments": []
    }
    
    print("\n⚡ Réchauffement...")
    
    if bert:
        await asyncio.gather(
            text.analyze(dummy),
            url.analyze(dummy),
            rag.query_email("test", "test"),
            return_exceptions=True
        )
    else:
        await asyncio.gather(
            text.analyze(dummy),
            url.analyze(dummy),
            rag.query_email("test", "test"),
            return_exceptions=True
        )
    
    print("\n✅ Système prêt!")
    print("\n💡 Lance: python test_10_emails.py full\n")

if __name__ == "__main__":
    asyncio.run(warmup())