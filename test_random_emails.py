"""
test_random_emails.py - Test Ghost Sentry with RANDOM emails from ChromaDB
Each run selects different random URLs from the 11,000+ phishing database
"""

import warnings
import logging
import asyncio
import json
import random
from datetime import datetime

# Suppress warnings
warnings.filterwarnings("ignore")
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub").setLevel(logging.ERROR)
logging.getLogger("sentence_transformers").setLevel(logging.ERROR)
logging.getLogger("chromadb").setLevel(logging.ERROR)
logging.getLogger("transformers").setLevel(logging.ERROR)

from orchestrator import analyze_email
import chromadb

# ============================================
# LOAD RANDOM URLS FROM CHROMADB
# ============================================

def get_random_phishing_urls(count=5):
    """Extract random URLs from ChromaDB (phishing database)"""
    
    print(f"🔄 Loading {count} random URLs from ChromaDB...")
    
    # Connect to ChromaDB
    client = chromadb.PersistentClient(path="data/chromadb")
    collection = client.get_collection("urlhaus_urls")
    
    # Get ALL URLs from database
    all_data = collection.get()
    all_urls = all_data['documents']
    
    # Randomly select 'count' URLs
    random_urls = random.sample(all_urls, min(count, len(all_urls)))
    
    print(f"✅ Selected {len(random_urls)} random URLs from {len(all_urls)} total in ChromaDB\n")
    
    return random_urls

# ============================================
# RANDOM EMAIL GENERATORS
# ============================================

def random_phishing_subject(url):
    """Generate a random phishing subject based on URL content"""
    
    # Detect brand from URL
    brands = ["paypal", "amazon", "apple", "microsoft", "chase", 
              "wellsfargo", "bank", "google", "facebook", "netflix",
              "dropbox", "adobe", "instagram", "linkedin"]
    
    brand = "account"
    for b in brands:
        if b in url.lower():
            brand = b
            break
    
    subjects = [
        f"⚠️ URGENT: Your {brand.title()} account has been suspended",
        f"Security Alert: Unusual activity on your {brand.title()} account",
        f"Action Required: Verify your {brand.title()} account now",
        f"Your {brand.title()} account will be closed within 24 hours",
        f"Important: Update your {brand.title()} payment information",
        f"Someone tried to access your {brand.title()} account",
        f"{brand.title()} Security: Your account has been locked",
        f"Immediate action needed: {brand.title()} account verification"
    ]
    
    return random.choice(subjects)

def random_phishing_body(url):
    """Generate a random phishing email body"""
    
    bodies = [
        f"Dear customer,\n\nWe detected unusual activity on your account. Please verify immediately:\n🔗 {url}\n\nFailure to verify within 24 hours will result in account suspension.\n\nSincerely,\nSecurity Team",
        
        f"Security Alert!\n\nSomeone tried to access your account from an unrecognized device. If this wasn't you, please verify your identity here:\n{url}\n\nThank you,\nAccount Protection Team",
        
        f"Action Required!\n\nYour account has been temporarily limited due to suspicious activity. To restore access, please confirm your information:\n{url}\n\nThis must be completed within 24 hours.",
        
        f"Important Notice!\n\nWe need you to confirm your account information to continue using our services. Click the link below to verify:\n{url}\n\nThank you for your cooperation.",
        
        f"Your account has been selected for verification.\n\nPlease complete the verification process within 48 hours:\n{url}\n\nIf you don't verify, your account will be suspended."
    ]
    
    return random.choice(bodies)

def random_sender(url):
    """Generate a random suspicious sender email"""
    
    domains = ["security", "alert", "verify", "account", "support", "protection"]
    tlds = [".com", ".net", ".org", ".info"]
    
    # Try to extract brand from URL
    brands = ["paypal", "amazon", "apple", "microsoft", "chase"]
    brand = random.choice(brands)
    for b in brands:
        if b in url.lower():
            brand = b
            break
    
    domain = random.choice(domains)
    tld = random.choice(tlds)
    
    return f"{domain}@{brand}-{domain}{tld}"

def create_random_phishing_email(url, index):
    """Create a completely random phishing email from a URL"""
    
    return {
        "uid": f"random_phish_{index:03d}_{random.randint(1000, 9999)}",
        "from": random_sender(url),
        "subject": random_phishing_subject(url),
        "body_text": random_phishing_body(url),
        "urls": [url],
        "attachments": []
    }

def create_random_legitimate_email(index):
    """Create a random legitimate email (no phishing URLs)"""
    
    legit_senders = [
        "newsletter@medium.com", "noreply@github.com", "calendar@google.com",
        "trello@trello.com", "slack@slack.com", "welcome@linkedin.com",
        "notifications@twitter.com", "info@spotify.com", "team@dropbox.com",
        "updates@netflix.com", "hello@notion.com", "mail@substack.com"
    ]
    
    legit_subjects = [
        "Your weekly digest is ready",
        "Someone commented on your pull request",
        "Meeting reminder: Team sync tomorrow",
        "You have 3 cards due today",
        "Unread messages in #general",
        "Your monthly report is available",
        "New login from Chrome browser",
        "Your subscription receipt",
        "Welcome to the team!",
        "Security update: Two-factor authentication"
    ]
    
    legit_bodies = [
        "Here are your updates for this week. Click here to read more.",
        "Your request has been processed successfully. No action needed.",
        "Just a friendly reminder about your upcoming meeting.",
        "You have new notifications. Check your dashboard.",
        "Thank you for being a valued customer. Here's what's new."
    ]
    
    legit_urls = [
        "https://medium.com", "https://github.com", "https://calendar.google.com",
        "https://trello.com", "https://slack.com", "https://linkedin.com",
        "https://twitter.com", "https://spotify.com", "https://dropbox.com",
        "https://netflix.com"
    ]
    
    return {
        "uid": f"random_legit_{index:03d}_{random.randint(1000, 9999)}",
        "from": random.choice(legit_senders),
        "subject": random.choice(legit_subjects),
        "body_text": random.choice(legit_bodies),
        "urls": [random.choice(legit_urls)],
        "attachments": []
    }

# ============================================
# MAIN TEST FUNCTION
# ============================================

async def test_random_10_emails():
    """Test with 5 legitimate + 5 random phishing emails from ChromaDB"""
    
    print("\n" + "=" * 80)
    print("🔬 GHOST SENTRY - RANDOM 10 EMAIL TEST")
    print("=" * 80)
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    print("\n🎲 GENERATING RANDOM EMAILS...\n")
    
    # Get 5 random URLs from ChromaDB
    random_urls = get_random_phishing_urls(count=5)
    
    print("🎣 RANDOM PHISHING URLS SELECTED FOR THIS TEST:")
    for i, url in enumerate(random_urls, 1):
        print(f"   {i}. {url[:80]}...")
    
    # Create 5 random phishing emails from these URLs
    phishing_emails = []
    for i, url in enumerate(random_urls, 1):
        email = create_random_phishing_email(url, i)
        phishing_emails.append(email)
    
    # Create 5 random legitimate emails
    legitimate_emails = [create_random_legitimate_email(i) for i in range(1, 6)]
    
    # Combine and shuffle
    all_emails = legitimate_emails + phishing_emails
    random.shuffle(all_emails)
    
    print("\n" + "-" * 80)
    print("📧 ANALYZING 10 RANDOM EMAILS:")
    print("-" * 80)
    
    results = []
    
    for email in all_emails:
        result = await analyze_email(email)
        
        is_phishing = email['uid'].startswith("random_phish")
        is_correct = (is_phishing and result.verdict in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]) or \
                     (not is_phishing and result.verdict == "CLEAN")
        
        status = "✅" if is_correct else "❌"
        
        print(f"\n{status} {email['uid']}")
        print(f"   From: {email['from']}")
        print(f"   Subject: {email['subject'][:55]}...")
        print(f"   Verdict: {result.verdict}")
        print(f"   Score: {result.score_final:.4f}")
        print(f"   Scores: T={result.scores['text']:.3f} | U={result.scores['url']:.3f} | R={result.scores['rag']:.3f} | B={result.scores['bert']:.3f}")
        
        if is_phishing and 'urls' in email and email['urls']:
            print(f"   Test URL: {email['urls'][0][:60]}...")
            print(f"   RAG Score: {result.scores['rag']:.3f} (similarity to known phishing)")
        
        results.append({
            "uid": email['uid'],
            "is_phishing": is_phishing,
            "verdict": result.verdict,
            "score": result.score_final,
            "url": email['urls'][0] if is_phishing and email['urls'] else None,
            "rag_score": result.scores['rag'] if is_phishing else None
        })
    
    # Calculate statistics
    correct = sum(1 for r in results if (r['is_phishing'] and r['verdict'] in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]) or 
                  (not r['is_phishing'] and r['verdict'] == "CLEAN"))
    
    print("\n" + "=" * 80)
    print("📊 SUMMARY")
    print("=" * 80)
    
    print(f"\n🎯 ACCURACY: {correct}/10 ({correct*10:.0f}%)")
    
    if correct == 10:
        print("🎉 PERFECT! All random phishing URLs detected!")
    elif correct >= 8:
        print("👍 GOOD! Most phishing URLs detected.")
    else:
        print("⚠️ Some phishing URLs were missed. Consider tuning thresholds.")
    
    # Show which phishing URLs were detected
    print("\n🎣 PHISHING URL DETECTION RESULTS:")
    for r in results:
        if r['is_phishing']:
            detected = "✅ DETECTED" if r['verdict'] in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"] else "❌ MISSED"
            print(f"   {detected} | Score: {r['score']:.3f} | RAG: {r['rag_score']:.3f} | URL: {r['url'][:55]}...")
    
    # Save results
    output = {
        "timestamp": datetime.now().isoformat(),
        "accuracy": f"{correct}/10",
        "random_urls_used": random_urls,
        "results": results
    }
    
    with open("test_results_random.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\n💾 Results saved to: test_results_random.json")
    print("=" * 80)

# ============================================
# RUN MULTIPLE TESTS (To prove randomness)
# ============================================

async def run_multiple_tests(num_tests=3):
    """Run multiple random tests to show different URLs each time"""
    
    for test_num in range(1, num_tests + 1):
        print(f"\n{'='*80}")
        print(f"🧪 TEST #{test_num}")
        print(f"{'='*80}")
        await test_random_10_emails()
        
        if test_num < num_tests:
            print("\n⏳ Waiting 2 seconds before next test...")
            await asyncio.sleep(2)

# ============================================
# QUICK TEST (1 random phishing email)
# ============================================

async def quick_random_test():
    """Quick test with 1 random phishing URL"""
    
    print("\n" + "=" * 60)
    print("🎲 QUICK RANDOM PHISHING TEST")
    print("=" * 60)
    
    random_urls = get_random_phishing_urls(count=1)
    url = random_urls[0]
    
    print(f"\n📎 Testing URL: {url}")
    
    email = create_random_phishing_email(url, 1)
    result = await analyze_email(email)
    
    print(f"\n📊 Result:")
    print(f"   Verdict: {result.verdict}")
    print(f"   Final Score: {result.score_final:.4f}")
    print(f"   URL Score: {result.scores['url']:.3f}")
    print(f"   RAG Score: {result.scores['rag']:.3f}")
    print(f"   Reason: {result.reason[:100]}...")

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "quick":
            asyncio.run(quick_random_test())
        elif sys.argv[1] == "multi":
            count = int(sys.argv[2]) if len(sys.argv) > 2 else 3
            asyncio.run(run_multiple_tests(count))
        else:
            print("Usage:")
            print("  python test_random_emails.py           # Run 10 random emails")
            print("  python test_random_emails.py quick     # Test 1 random URL")
            print("  python test_random_emails.py multi 5   # Run 5 consecutive tests")
    else:
        asyncio.run(test_random_10_emails())