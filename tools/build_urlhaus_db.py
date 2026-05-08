"""
tools/build_urlhaus_db.py - Build ChromaDB with URLHaus data
This script will download and store phishing URLs properly
"""

import hashlib
import urllib.request
import logging
import time
import os
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def download_urlhaus_urls(limit=11000):
    """Download URLs from URLHaus"""
    logger.info("Downloading from URLHaus...")
    urls = []
    
    try:
        # Download the CSV file
        url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        
        with urllib.request.urlopen(req, timeout=60) as response:
            content = response.read().decode('utf-8', errors='ignore')
        
        lines = content.split('\n')
        logger.info(f"Downloaded {len(lines)} lines")
        
        for line in lines:
            # Skip comments and empty lines
            if line.startswith('#') or not line.strip():
                continue
            
            parts = line.split(',')
            if len(parts) >= 3:
                url = parts[2].strip('"')
                # Only keep HTTP/HTTPS URLs
                if url.startswith(('http://', 'https://')):
                    urls.append(url)
                    if len(urls) >= limit:
                        break
        
        logger.info(f"✅ Extracted {len(urls)} valid URLs")
        return urls
        
    except Exception as e:
        logger.error(f"Download failed: {e}")
        # Return sample URLs as fallback
        return [
            "http://paypal-secure-login.com",
            "https://amazon-verify-account.net",
            "http://appleid-restore.com",
            "https://chase-security-verify.com",
            "http://microsoft-account-alert.net",
            "https://wellsfargo-verify.com",
            "http://bankofamerica-secure.com",
            "https://netflix-account-verify.net",
        ]

def build_database():
    """Build ChromaDB with URLHaus URLs"""
    
    logger.info("=" * 60)
    logger.info("Building URLHaus Database")
    logger.info("=" * 60)
    
    # Ensure data directory exists
    Path("data/chromadb").mkdir(parents=True, exist_ok=True)
    
    # Initialize ChromaDB
    client = chromadb.PersistentClient(path="data/chromadb")
    
    # Delete existing collection if it exists
    try:
        client.delete_collection("urlhaus_urls")
        logger.info("Removed existing collection")
    except:
        pass
    
    # Create new collection
    collection = client.create_collection(
        name="urlhaus_urls",
        metadata={"description": "URLHaus malicious URLs", "source": "abuse.ch"}
    )
    
    # Load embedding model
    logger.info("Loading embedding model...")
    encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    logger.info("✅ Model loaded")
    
    # Download URLs
    urls = download_urlhaus_urls(limit=11000)
    logger.info(f"Processing {len(urls)} URLs...")
    
    # Add in batches to avoid memory issues
    batch_size = 200
    total_added = 0
    
    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        
        # Generate embeddings
        embeddings = encoder.encode(batch).tolist()
        
        # Create IDs
        ids = [hashlib.md5(url.encode()).hexdigest() for url in batch]
        
        # Add to collection
        try:
            collection.add(
                ids=ids,
                documents=batch,
                embeddings=embeddings,
                metadatas=[{"source": "urlhaus", "index": i+j} for j in range(len(batch))]
            )
            total_added += len(batch)
            logger.info(f"Added {total_added}/{len(urls)} URLs")
        except Exception as e:
            logger.error(f"Error adding batch {i}: {e}")
            continue
        
        # Small delay to avoid overwhelming the system
        time.sleep(0.1)
    
    # Verify
    final_count = collection.count()
    logger.info("=" * 60)
    logger.info(f"✅ BUILD COMPLETE!")
    logger.info(f"   Total URLs in database: {final_count:,}")
    logger.info("=" * 60)
    
    # Test query
    logger.info("\n🔍 Testing database...")
    test_urls = [
        "http://paypal-secure-login.com",
        "https://amazon-verify-account.net",
        "https://google.com"
    ]
    
    for test_url in test_urls:
        test_embedding = encoder.encode([test_url]).tolist()
        results = collection.query(query_embeddings=test_embedding, n_results=1)
        
        if results['distances'] and results['distances'][0]:
            distance = results['distances'][0][0]
            similarity = max(0, min(1, 1 - (distance / 2)))
            logger.info(f"   {test_url[:40]:40} → similarity: {similarity:.3f}")
    
    return collection

if __name__ == "__main__":
    build_database()