"""
test_10_emails.py - Test Ghost Sentry with 5 legitimate + 5 phishing emails
Run this after ChromaDB is built to verify detection accuracy
"""

import asyncio
import json
from datetime import datetime
from orchestrator import analyze_email

# ============================================
# 5 LEGITIMATE (GOOD) EMAILS
# ============================================

GOOD_EMAILS = [
    {
        "uid": "good_001",
        "from": "newsletter@medium.com",
        "subject": "Your weekly digest: New stories you might like",
        "body_text": """
        Hi reader,
        
        Here are this week's top stories:
        - The future of AI in cybersecurity
        - 10 Python tips for beginners
        - Remote work best practices
        
        Read more on Medium.com
        """,
        "urls": ["https://medium.com"],
        "attachments": []
    },
    {
        "uid": "good_002",
        "from": "calendar@google.com",
        "subject": "Meeting reminder: Team sync",
        "body_text": """
        You have an upcoming event:
        
        Title: Weekly Team Sync
        Time: Tomorrow at 10:00 AM
        Location: Google Meet
        
        Add to calendar or join directly.
        """,
        "urls": ["https://calendar.google.com"],
        "attachments": []
    },
    {
        "uid": "good_003",
        "from": "noreply@github.com",
        "subject": "[GitHub] Pull request approved",
        "body_text": """
        @colleague commented on your pull request #42:
        
        "Code looks good! Just fix the tests and we can merge."
        
        View this pull request: https://github.com/your-repo/pull/42
        """,
        "urls": ["https://github.com"],
        "attachments": []
    },
    {
        "uid": "good_004",
        "from": "trello@trello.com",
        "subject": "Trello: Cards due today",
        "body_text": """
        Here are your cards due today:
        
        📋 Complete project documentation - Due today
        📋 Review security audit - Due today
        📋 Update README - Due tomorrow
        
        View your board: https://trello.com/b/your-board
        """,
        "urls": ["https://trello.com"],
        "attachments": []
    },
    {
        "uid": "good_005",
        "from": "slack@slack.com",
        "subject": "Slack digest: Unread messages",
        "body_text": """
        You have unread messages in:
        - #general: Welcome message from @admin
        - #project-alpha: Update from @lead
        - #random: Meme of the day
        
        Catch up here: https://app.slack.com/client
        """,
        "urls": ["https://app.slack.com"],
        "attachments": []
    }
]

# ============================================
# 5 PHISHING (BAD) EMAILS
# ============================================

BAD_EMAILS = [
    {
        "uid": "bad_001",
        "from": "security@paypal-security.com",
        "subject": "⚠️ URGENT: Your PayPal account has been suspended",
        "body_text": """
        Dear Customer,
        
        We detected unusual activity on your PayPal account.
        
        To avoid permanent suspension, you MUST verify your account immediately:
        🔗 http://paypal-verify-account.com/secure/login
        
        Failure to verify within 24 hours will result in account closure.
        
        Thanks,
        PayPal Security Team
        """,
        "urls": ["http://paypal-verify-account.com/secure/login"],
        "attachments": []
    },
    {
        "uid": "bad_002",
        "from": "amazon-noreply@amazon-delivery-track.net",
        "subject": "Your Amazon package cannot be delivered",
        "body_text": """
        Dear Amazon Customer,
        
        Your package #AMZ-837492 has been delayed due to incorrect address.
        
        Please confirm your address here:
        🔗 https://amazon-address-verify.com/update-info
        
        If not confirmed within 12 hours, your order will be cancelled.
        
        Amazon Delivery Team
        """,
        "urls": ["https://amazon-address-verify.com/update-info"],
        "attachments": []
    },
    {
        "uid": "bad_003",
        "from": "appleid@apple-security.com",
        "subject": "Apple ID Security Alert: Account compromised",
        "body_text": """
        Dear Apple User,
        
        We detected a login attempt from an unrecognized device.
        
        Immediately secure your account:
        🔗 http://appleid-verify.com/restore-account
        
        Access will be permanently blocked if you ignore this message.
        
        Apple Security Center
        """,
        "urls": ["http://appleid-verify.com/restore-account"],
        "attachments": []
    },
    {
        "uid": "bad_004",
        "from": "bank@chase-alerts.com",
        "subject": "Chase Bank: Unusual activity detected",
        "body_text": """
        Dear Chase Customer,
        
        A transaction of $1,247.83 was attempted from an unrecognized device.
        
        Verify this transaction or your account will be locked:
        🔗 https://chase-security-verify.com/confirm-transaction
        
        Call us immediately at 1-800-XXX-XXXX if you did not authorize this.
        
        Chase Fraud Department
        """,
        "urls": ["https://chase-security-verify.com/confirm-transaction"],
        "attachments": []
    },
    {
        "uid": "bad_005",
        "from": "microsoft@account-security.net",
        "subject": "Microsoft Account: Action required - Sign-in from new device",
        "body_text": """
        Dear Microsoft User,
        
        We noticed a sign-in to your account from a Windows device in Russia.
        
        If this wasn't you, secure your account:
        🔗 https://microsoft-security-alert.com/recover-account
        
        Ignoring this will result in permanent account suspension.
        
        Microsoft Account Team
        """,
        "urls": ["https://microsoft-security-alert.com/recover-account"],
        "attachments": []
    }
]

async def test_10_emails():
    """Run full test with 5 good + 5 bad emails"""
    
    print("\n" + "=" * 80)
    print("🔬 GHOST SENTRY - 10 EMAIL TEST")
    print("=" * 80)
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    all_results = []
    
    # Test Good emails
    print("\n📧 LEGITIMATE EMAILS (Expected: CLEAN):")
    print("-" * 70)
    
    for email in GOOD_EMAILS:
        result = await analyze_email(email)
        all_results.append(("GOOD", result))
        
        is_correct = result.verdict == "CLEAN"
        status = "✅" if is_correct else "❌"
        
        print(f"\n{status} {email['uid']}")
        print(f"   From: {email['from']}")
        print(f"   Subject: {email['subject'][:50]}...")
        print(f"   Verdict: {result.verdict}")
        print(f"   Score: {result.score_final:.4f}")
        print(f"   Scores: T={result.scores['text']:.3f} | U={result.scores['url']:.3f} | R={result.scores['rag']:.3f} | B={result.scores['bert']:.3f}")
        print(f"   Reason: {result.reason[:80]}...")
    
    # Test Bad emails
    print("\n" + "-" * 70)
    print("🎣 PHISHING EMAILS (Expected: SUSPICIOUS/MALICIOUS):")
    print("-" * 70)
    
    for email in BAD_EMAILS:
        result = await analyze_email(email)
        all_results.append(("BAD", result))
        
        is_correct = result.verdict in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]
        status = "✅" if is_correct else "❌"
        
        print(f"\n{status} {email['uid']}")
        print(f"   From: {email['from']}")
        print(f"   Subject: {email['subject'][:50]}...")
        print(f"   Verdict: {result.verdict}")
        print(f"   Score: {result.score_final:.4f}")
        print(f"   Scores: T={result.scores['text']:.3f} | U={result.scores['url']:.3f} | R={result.scores['rag']:.3f} | B={result.scores['bert']:.3f}")
        print(f"   Reason: {result.reason[:80]}...")
    
    # Calculate statistics
    print("\n" + "=" * 80)
    print("📊 SUMMARY")
    print("=" * 80)
    
    correct = 0
    for expected, result in all_results:
        if expected == "GOOD" and result.verdict == "CLEAN":
            correct += 1
        elif expected == "BAD" and result.verdict in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]:
            correct += 1
    
    accuracy = (correct / len(all_results)) * 100
    
    print(f"\n🎯 ACCURACY: {correct}/{len(all_results)} ({accuracy:.1f}%)")
    
    if accuracy >= 90:
        print("🎉 EXCELLENT! Your AI phishing detection is production-ready!")
    elif accuracy >= 70:
        print("👍 GOOD! Your system detects most phishing attempts.")
    else:
        print("⚠️ Consider tuning thresholds or adding more training data.")
    
    # Detailed stats
    good_scores = [r.score_final for e, r in all_results if e == "GOOD"]
    bad_scores = [r.score_final for e, r in all_results if e == "BAD"]
    
    print(f"\n📈 STATISTICS:")
    print(f"   Legitimate emails avg score: {sum(good_scores)/len(good_scores):.4f}")
    print(f"   Phishing emails avg score:   {sum(bad_scores)/len(bad_scores):.4f}")
    print(f"   Separation margin: {sum(bad_scores)/len(bad_scores) - sum(good_scores)/len(good_scores):.4f}")
    
    # RAG impact analysis
    rag_scores_good = [r.scores['rag'] for e, r in all_results if e == "GOOD"]
    rag_scores_bad = [r.scores['rag'] for e, r in all_results if e == "BAD"]
    
    print(f"\n🧠 RAG (ChromaDB) Impact:")
    print(f"   Avg RAG score for legitimate: {sum(rag_scores_good)/len(rag_scores_good):.4f}")
    print(f"   Avg RAG score for phishing:   {sum(rag_scores_bad)/len(rag_scores_bad):.4f}")
    
    # Save detailed results
    output = {
        "timestamp": datetime.now().isoformat(),
        "accuracy": f"{correct}/{len(all_results)} ({accuracy:.1f}%)",
        "results": []
    }
    
    for expected, result in all_results:
        output["results"].append({
            "uid": result.uid,
            "expected": expected,
            "verdict": result.verdict,
            "score": result.score_final,
            "scores": result.scores,
            "reason": result.reason,
            "groq_used": result.groq_analysis is not None
        })
    
    with open("test_results_10_emails.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: test_results_10_emails.json")
    print("=" * 80)
    
    # Show misclassifications if any
    misclassified = []
    for expected, result in all_results:
        if expected == "GOOD" and result.verdict != "CLEAN":
            misclassified.append(("GOOD", result))
        elif expected == "BAD" and result.verdict not in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]:
            misclassified.append(("BAD", result))
    
    if misclassified:
        print("\n⚠️ MISCLASSIFICATIONS:")
        for expected, result in misclassified:
            print(f"   {result.uid}: Expected {expected}, got {result.verdict} (score: {result.score_final:.4f})")
    
    return all_results

async def quick_test():
    """Quick test with 1 good and 1 bad email"""
    
    print("\n" + "=" * 60)
    print("🔬 GHOST SENTRY - QUICK TEST (1 Good + 1 Bad)")
    print("=" * 60)
    
    # Test good email
    print("\n📧 GOOD EMAIL TEST:")
    print("-" * 40)
    result = await analyze_email(GOOD_EMAILS[0])
    print(f"   From: {GOOD_EMAILS[0]['from']}")
    print(f"   Subject: {GOOD_EMAILS[0]['subject']}")
    print(f"   Verdict: {result.verdict}")
    print(f"   Score: {result.score_final:.4f}")
    print(f"   RAG Score: {result.scores['rag']:.4f}")
    print(f"   Expected: CLEAN → {'✅ PASS' if result.verdict == 'CLEAN' else '❌ FAIL'}")
    
    # Test phishing email
    print("\n🎣 PHISHING EMAIL TEST:")
    print("-" * 40)
    result = await analyze_email(BAD_EMAILS[0])
    print(f"   From: {BAD_EMAILS[0]['from']}")
    print(f"   Subject: {BAD_EMAILS[0]['subject']}")
    print(f"   Verdict: {result.verdict}")
    print(f"   Score: {result.score_final:.4f}")
    print(f"   RAG Score: {result.scores['rag']:.4f}")
    expected_bad = result.verdict in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]
    print(f"   Expected: SUSPICIOUS/MALICIOUS → {'✅ PASS' if expected_bad else '❌ FAIL'}")
    
    print("\n" + "=" * 60)

async def detailed_analysis():
    """Run detailed analysis with score breakdowns"""
    
    print("\n" + "=" * 80)
    print("🔬 GHOST SENTRY - DETAILED ANALYSIS")
    print("=" * 80)
    
    print("\n📊 Score Breakdown for Phishing Email:")
    print("-" * 50)
    
    result = await analyze_email(BAD_EMAILS[0])
    
    print(f"\n   Email: {BAD_EMAILS[0]['subject'][:60]}...")
    print(f"\n   Final Verdict: {result.verdict}")
    print(f"   Final Score: {result.score_final:.4f}")
    print(f"\n   Component Scores:")
    print(f"   ┌─────────────────┬─────────┬─────────┐")
    print(f"   │ Component       │ Score   │ Weight  │")
    print(f"   ├─────────────────┼─────────┼─────────┤")
    print(f"   │ Text Pipeline   │ {result.scores['text']:.3f}     │ 20%     │")
    print(f"   │ URL Pipeline    │ {result.scores['url']:.3f}     │ 30%     │")
    print(f"   │ RAG (ChromaDB)  │ {result.scores['rag']:.3f}     │ 20%     │")
    print(f"   │ BERT Classifier │ {result.scores['bert']:.3f}     │ 30%     │")
    print(f"   └─────────────────┴─────────┴─────────┘")
    
    print(f"\n   Reasoning: {result.reason}")
    
    if result.groq_analysis:
        print(f"\n   🤖 Groq Analysis: {result.groq_analysis[:150]}...")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "full":
            asyncio.run(test_10_emails())
        elif sys.argv[1] == "detail":
            asyncio.run(detailed_analysis())
        elif sys.argv[1] == "quick":
            asyncio.run(quick_test())
        else:
            print("Usage: python test_10_emails.py [full|quick|detail]")
            print("  full   - Test all 10 emails")
            print("  quick  - Test 1 good + 1 bad email")
            print("  detail - Show detailed score breakdown")
    else:
        # Default: run quick test
        asyncio.run(quick_test())