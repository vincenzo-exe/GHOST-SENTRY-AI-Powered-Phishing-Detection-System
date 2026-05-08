"""
tools/chroma_rag.py — RAG Engine for Ghost Sentry
Compatible with links_db.py builder - queries 10k+ URLHaus database
"""

import logging
import hashlib
from typing import List, Dict, Optional
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ChromaRAG:
    """Query ChromaDB vector database for phishing similarity."""
    
    def __init__(self, persist_dir: str = "data/chromadb"):
        """Initialize ChromaDB client and embedding model."""
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        self.client = None
        self.url_collection = None
        self.email_collection = None
        self.encoder = None
        
        try:
            # Initialize ChromaDB client
            self.client = chromadb.PersistentClient(path=str(self.persist_dir))
            
            # Get existing collections (created by links_db.py)
            try:
                self.url_collection = self.client.get_collection("urlhaus_urls")
                url_count = self.url_collection.count()
                logger.info(f"✅ Loaded URL collection: {url_count:,} URLs from URLHaus")
            except Exception as e:
                logger.warning(f"URL collection not found: {e}")
                logger.warning("Run 'python tools/links_db.py' first to build database")
                self.url_collection = self.client.create_collection("urlhaus_urls")
            
            try:
                self.email_collection = self.client.get_collection("phishing_emails")
                email_count = self.email_collection.count()
                logger.info(f"✅ Loaded email collection: {email_count} emails")
            except Exception:
                self.email_collection = None
                # Email collection is optional
            
            # Load embedding model (same as links_db.py)
            self.encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
            logger.info("✅ Embedding model loaded (MiniLM-L6-v2)")
            
        except Exception as e:
            logger.error(f"ChromaRAG initialization failed: {e}")
    
    def _get_embedding(self, text: str) -> List[float]:
        """Generate embedding for text."""
        if not self.encoder:
            return [0.0] * 384
        embedding = self.encoder.encode(text).tolist()
        return embedding
    
    async def query_url(self, url: str) -> float:
        """
        Query URL collection for similar malicious URLs.
        Returns similarity score 0-1.
        Higher score = more similar to known phishing URLs.
        """
        if not self.url_collection or not self.encoder:
            logger.debug("ChromaDB not available")
            return 0.0
        
        try:
            # Normalize URL
            url_normalized = url.lower().strip()
            
            # Generate embedding
            embedding = self._get_embedding(url_normalized)
            
            # Query collection for top matches
            results = self.url_collection.query(
                query_embeddings=[embedding],
                n_results=5,
                include=["distances", "documents"]
            )
            
            if not results['distances'] or len(results['distances'][0]) == 0:
                return 0.0
            
            # Convert distances to similarities
            distances = results['distances'][0]
            
            # Weighted average (more weight on closest matches)
            weights = [0.4, 0.25, 0.15, 0.1, 0.1][:len(distances)]
            weighted_distance = sum(d * w for d, w in zip(distances, weights))
            
            # Convert to similarity (0-1 scale)
            # Distance range: 0 (identical) to ~2 (very different)
            max_distance = 2.0
            similarity = max(0.0, min(1.0, 1.0 - (weighted_distance / max_distance)))
            
            # Boost if we have very close match
            if distances[0] < 0.3:
                similarity = min(1.0, similarity * 1.2)
            
            if similarity > 0.3:
                logger.debug(f"URL match: {similarity:.3f} for {url[:50]}")
            
            return similarity
            
        except Exception as e:
            logger.error(f"URL query failed: {e}")
            return 0.0
    
    async def query_email(self, subject: str, body: str) -> float:
        """
        Query email collection for similar phishing emails.
        Returns similarity score 0-1.
        """
        if not self.email_collection or not self.encoder:
            logger.debug("Email collection not available")
            return 0.0
        
        try:
            # Combine subject and body (limited length)
            query_text = f"{subject}\n{body[:1000]}"
            
            embedding = self._get_embedding(query_text)
            
            results = self.email_collection.query(
                query_embeddings=[embedding],
                n_results=5,
                include=["distances"]
            )
            
            if not results['distances'] or len(results['distances'][0]) == 0:
                return 0.0
            
            distances = results['distances'][0]
            weights = [0.4, 0.25, 0.15, 0.1, 0.1][:len(distances)]
            weighted_distance = sum(d * w for d, w in zip(distances, weights))
            
            max_distance = 2.0
            similarity = max(0.0, min(1.0, 1.0 - (weighted_distance / max_distance)))
            
            return similarity
            
        except Exception as e:
            logger.error(f"Email query failed: {e}")
            return 0.0
    
    async def query(self, text: str) -> float:
        """Generic query - auto-detects if URL or text."""
        if text.startswith(("http://", "https://")):
            return await self.query_url(text)
        else:
            return await self.query_email(text, text)
    
    def get_stats(self) -> Dict:
        """Get database statistics."""
        stats = {
            "urls": 0,
            "emails": 0,
            "persist_dir": str(self.persist_dir)
        }
        if self.url_collection:
            stats["urls"] = self.url_collection.count()
        if self.email_collection:
            stats["emails"] = self.email_collection.count()
        return stats


async def test():
    """Test ChromaRAG functionality."""
    print("\n" + "=" * 60)
    print("🔍 ChromaRAG Test")
    print("=" * 60)
    
    rag = ChromaRAG()
    stats = rag.get_stats()
    
    print(f"\n📊 Database Stats:")
    print(f"   URLs in database: {stats['urls']:,}")
    print(f"   Emails in database: {stats['emails']}")
    print(f"   Storage: {stats['persist_dir']}")
    
    if stats['urls'] == 0:
        print("\n⚠️  No URLs found in database!")
        print("   Run this first to build the database:")
        print("   python tools/links_db.py")
        return
    
    print("\n🎯 Testing URL Queries:")
    print("-" * 40)
    
    test_urls = [
        "http://paypal-secure-login.com",
        "https://amazon-verify-account.net",
        "https://google.com",
        "http://appleid-restore.com"
    ]
    
    for url in test_urls:
        score = await rag.query_url(url)
        threat_level = "🔴 HIGH" if score > 0.5 else "🟡 MEDIUM" if score > 0.3 else "🟢 LOW"
        print(f"   {threat_level} {score:.3f} | {url[:50]}")
    
    print("\n✅ ChromaRAG test complete!")


if __name__ == "__main__":
    import asyncio
    asyncio.run(test())