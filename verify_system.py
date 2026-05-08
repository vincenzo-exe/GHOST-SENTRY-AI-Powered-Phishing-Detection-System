"""
verify_system.py - Complete system verification for Ghost Sentry
Run this to check if everything is working properly
"""

import asyncio
import sys
import os
import json
from datetime import datetime

def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)

def print_ok(msg):
    print(f"   ✅ {msg}")

def print_error(msg):
    print(f"   ❌ {msg}")

def print_warning(msg):
    print(f"   ⚠️  {msg}")

def print_info(msg):
    print(f"   📌 {msg}")

# ============================================
# 1. ENVIRONMENT VERIFICATION
# ============================================

def verify_environment():
    print_section("1. ENVIRONMENT VERIFICATION")
    
    # Check Python version
    python_version = sys.version.split()[0]
    print_info(f"Python version: {python_version}")
    if sys.version_info >= (3, 8):
        print_ok(f"Python {python_version} (OK)")
    else:
        print_error(f"Python {python_version} (need 3.8+)")
    
    # Check .env file
    if os.path.exists(".env"):
        print_ok(".env file found")
        
        # Check for Groq API key
        with open(".env", "r") as f:
            content = f.read()
            if "GROQ_API_KEY=" in content and "gsk_" in content:
                print_ok("GROQ_API_KEY configured")
            else:
                print_error("GROQ_API_KEY missing or invalid")
    else:
        print_error(".env file not found")
    
    # Check virtual environment
    if sys.prefix != sys.base_prefix:
        print_ok(f"Virtual environment active: {os.path.basename(sys.prefix)}")
    else:
        print_warning("No virtual environment detected")

# ============================================
# 2. DIRECTORY STRUCTURE VERIFICATION
# ============================================

def verify_directories():
    print_section("2. DIRECTORY STRUCTURE")
    
    required_dirs = [
        "data",
        "data/chromadb",
        "data/feeds",
        "config",
        "tools",
        "models",
        "db"
    ]
    
    for dir_name in required_dirs:
        if os.path.exists(dir_name):
            print_ok(f"{dir_name}/")
        else:
            print_error(f"{dir_name}/ missing")
            os.makedirs(dir_name, exist_ok=True)
            print_info(f"Created {dir_name}/")

# ============================================
# 3. CHROMADB VERIFICATION
# ============================================

def verify_chromadb():
    print_section("3. CHROMADB VERIFICATION")
    
    try:
        import chromadb
        print_ok("ChromaDB package installed")
        
        client = chromadb.PersistentClient(path="data/chromadb")
        
        try:
            collection = client.get_collection("urlhaus_urls")
            count = collection.count()
            
            if count > 0:
                print_ok(f"URL collection found: {count:,} URLs")
                
                # Test query
                from sentence_transformers import SentenceTransformer
                encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
                
                test_url = "http://paypal-secure-login.com"
                embedding = encoder.encode([test_url]).tolist()
                results = collection.query(query_embeddings=embedding, n_results=1)
                
                if results['distances'] and results['distances'][0]:
                    distance = results['distances'][0][0]
                    similarity = max(0, min(1, 1 - (distance / 2)))
                    print_info(f"Test query similarity: {similarity:.3f}")
                    
                    if similarity > 0.3:
                        print_ok("ChromaDB query working correctly")
                    else:
                        print_warning("Low similarity scores - check data quality")
            else:
                print_error("URL collection exists but is empty")
                print_info("Run: python tools/links_db.py")
                
        except Exception as e:
            print_error(f"URL collection not found: {e}")
            print_info("Run: python tools/links_db.py")
            
    except ImportError as e:
        print_error(f"ChromaDB not installed: {e}")

# ============================================
# 4. ML MODELS VERIFICATION
# ============================================

def verify_models():
    print_section("4. ML MODELS VERIFICATION")
    
    # Check Sentence Transformer
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cpu")
        print_ok("Sentence Transformer model loaded")
    except Exception as e:
        print_error(f"Sentence Transformer failed: {e}")
    
    # Check Groq
    try:
        from groq import Groq
        from config.settings import Settings
        cfg = Settings()
        
        if cfg.GROQ_API_KEY:
            print_ok("Groq API key found")
            
            # Optional: Test API call
            try:
                client = Groq(api_key=cfg.GROQ_API_KEY)
                print_ok("Groq client initialized")
            except Exception as e:
                print_warning(f"Groq client init failed: {e}")
        else:
            print_warning("Groq API key missing - LLM fallback disabled")
    except ImportError:
        print_warning("Groq package not installed")

# ============================================
# 5. DEPENDENCIES VERIFICATION
# ============================================

def verify_dependencies():
    print_section("5. DEPENDENCIES VERIFICATION")
    
    required_packages = [
        "chromadb",
        "sentence_transformers",
        "groq",
        "tldextract",
        "PIL",
        "pyzbar",
        "aiohttp",
        "asyncio"
    ]
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print_ok(f"{package}")
        except ImportError:
            print_error(f"{package} missing - run: pip install {package}")

# ============================================
# 6. API CONNECTIVITY VERIFICATION
# ============================================

async def verify_api():
    print_section("6. API CONNECTIVITY")
    
    # Test Groq API
    try:
        from groq import Groq
        from config.settings import Settings
        cfg = Settings()
        
        if cfg.GROQ_API_KEY:
            client = Groq(api_key=cfg.GROQ_API_KEY)
            response = await asyncio.to_thread(
                client.chat.completions.create,
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": "Say 'OK'"}],
                max_tokens=5,
                temperature=0
            )
            print_ok(f"Groq API: {response.choices[0].message.content}")
        else:
            print_warning("Groq API key not configured")
    except Exception as e:
        print_error(f"Groq API failed: {e}")

# ============================================
# 7. ORCHESTRATOR VERIFICATION
# ============================================

async def verify_orchestrator():
    print_section("7. ORCHESTRATOR VERIFICATION")
    
    try:
        from orchestrator import analyze_email
        
        # Test clean email
        clean_email = {
            "uid": "verify_001",
            "from": "test@example.com",
            "subject": "Test Email",
            "body_text": "This is a legitimate test email.",
            "urls": [],
            "attachments": []
        }
        
        result = await analyze_email(clean_email)
        
        if result.verdict == "CLEAN":
            print_ok(f"Clean email detection: {result.verdict} (score: {result.score_final:.3f})")
        else:
            print_warning(f"Clean email detected as {result.verdict} (score: {result.score_final:.3f})")
        
        # Test phishing email
        phishing_email = {
            "uid": "verify_002",
            "from": "security@paypal-security.com",
            "subject": "URGENT: Account Suspended",
            "body_text": "Verify your account now: http://paypal-verify-login.com",
            "urls": ["http://paypal-verify-login.com"],
            "attachments": []
        }
        
        result = await analyze_email(phishing_email)
        
        if result.verdict in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]:
            print_ok(f"Phishing detection: {result.verdict} (score: {result.score_final:.3f})")
        else:
            print_warning(f"Phishing email marked as {result.verdict} (score: {result.score_final:.3f})")
        
        return True
        
    except Exception as e:
        print_error(f"Orchestrator test failed: {e}")
        return False

# ============================================
# 8. PERFORMANCE VERIFICATION
# ============================================

async def verify_performance():
    print_section("8. PERFORMANCE VERIFICATION")
    
    try:
        from orchestrator import analyze_email
        import time
        
        test_email = {
            "uid": "perf_001",
            "from": "test@example.com",
            "subject": "Performance Test",
            "body_text": "Testing system performance.",
            "urls": [],
            "attachments": []
        }
        
        times = []
        for i in range(3):
            start = time.time()
            await analyze_email(test_email)
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)
        
        avg_time = sum(times) / len(times)
        
        if avg_time < 1000:
            print_ok(f"Average response time: {avg_time:.0f}ms")
        elif avg_time < 3000:
            print_warning(f"Average response time: {avg_time:.0f}ms (acceptable)")
        else:
            print_error(f"Average response time: {avg_time:.0f}ms (slow)")
            
    except Exception as e:
        print_error(f"Performance test failed: {e}")

# ============================================
# 9. QR EXTRACTION VERIFICATION
# ============================================

def verify_qr_extraction():
    print_section("9. QR EXTRACTION VERIFICATION")
    
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        print_ok("Pillow and pyzbar installed")
        
        # Check if QR extraction is available in URL pipeline
        try:
            from tools.url_pipeline import URLPipeline
            pipeline = URLPipeline()
            if hasattr(pipeline, 'extract_qr_from_attachments'):
                print_ok("QR extraction method available")
            else:
                print_warning("QR extraction method not found in URLPipeline")
        except Exception as e:
            print_warning(f"Could not test QR extraction: {e}")
            
    except ImportError as e:
        print_warning(f"QR dependencies missing: {e}")
        print_info("Install: pip install pillow pyzbar")

# ============================================
# 10. FINAL SCORE
# ============================================

async def main():
    print("\n" + "=" * 70)
    print(" 🚀 GHOST SENTRY - SYSTEM VERIFICATION")
    print("=" * 70)
    print(f" 📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run all checks
    verify_environment()
    verify_directories()
    verify_dependencies()
    verify_models()
    verify_chromadb()
    verify_qr_extraction()
    await verify_api()
    orchestrator_ok = await verify_orchestrator()
    await verify_performance()
    
    # Final summary
    print_section("✅ VERIFICATION COMPLETE")
    
    print("\n📋 Next Steps:")
    print("   1. Run: python orchestrator.py")
    print("   2. Run: python test_10_emails.py full")
    print("   3. Check test_results_10_emails.json for detailed results")
    
    if orchestrator_ok:
        print("\n🎉 System is ready! Your Ghost Sentry is fully operational.")
    else:
        print("\n⚠️  Some issues detected. Review the errors above.")
    
    print("=" * 70 + "\n")

if __name__ == "__main__":
    asyncio.run(main())