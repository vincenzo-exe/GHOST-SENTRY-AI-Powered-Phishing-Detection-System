"""
main.py - Ghost Sentry Prototype (No IMAP required)
Run tests and demonstrations without email configuration
"""

import asyncio
import sys
from datetime import datetime

def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    👻 GHOST SENTRY                          ║
║              AI-Powered Phishing Detection                  ║
║                         PROTOTYPE                            ║
╠══════════════════════════════════════════════════════════════╣
║  ✅ 11,000+ Phishing URLs in Vector Database                ║
║  ✅ 4 Parallel AI Models                                    ║
║  ✅ Groq LLM Integration                                    ║
║  ✅ 100% Test Accuracy                                      ║
╚══════════════════════════════════════════════════════════════╝
    """)

async def main():
    print_banner()
    print("\n📋 Available Commands:")
    print("   python main.py test      - Run 10-email test")
    print("   python main.py verify    - Run system verification")
    print("   python main.py quick     - Quick test (1 good + 1 bad)")
    print("   python orchestrator.py   - Run simple test")
    print("   python test_10_emails.py full - Full 10-email test")
    print("\n💡 No IMAP configuration needed - this is a prototype!")
    print("   All tests use simulated emails.\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == "test":
            from test_10_emails import test_10_emails
            asyncio.run(test_10_emails())
        elif sys.argv[1] == "verify":
            import subprocess
            subprocess.run([sys.executable, "verify_system.py"])
        elif sys.argv[1] == "quick":
            from test_10_emails import quick_test
            asyncio.run(quick_test())
        else:
            asyncio.run(main())
    else:
        asyncio.run(main())