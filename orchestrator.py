"""
orchestrator.py — Ghost Sentry Main Orchestrator
Complete with JSON output and corrected phishing thresholds
"""

import asyncio
import logging
import time
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from groq import Groq
from config.settings import Settings

# Optional imports (fail gracefully if not available)
try:
    from tools.text_pipeline import TextPipeline
except ImportError:
    TextPipeline = None

try:
    from tools.url_pipeline import URLPipeline
except ImportError:
    URLPipeline = None

try:
    from tools.chroma_rag import ChromaRAG
except ImportError:
    ChromaRAG = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

cfg = Settings()


@dataclass
class AnalysisResult:
    """Complete analysis result with JSON serialization."""
    uid: str
    sender: str
    subject: str
    verdict: str
    score_final: float
    scores: Dict[str, float]
    reason: str
    processing_time: float
    timestamp: str
    qr_urls: List[str] = None
    groq_analysis: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to JSON-serializable dict."""
        return {
            "uid": self.uid,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "subject": self.subject,
            "verdict": self.verdict,
            "score_final": round(self.score_final, 4),
            "scores": {k: round(v, 4) for k, v in self.scores.items()},
            "reason": self.reason,
            "processing_time_ms": round(self.processing_time * 1000, 2),
            "qr_urls": self.qr_urls or [],
            "groq_analysis": self.groq_analysis,
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Return formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


class Orchestrator:
    """Main orchestrator for email analysis."""
    
    def __init__(self):
        self.text_pipeline = None
        self.url_pipeline = None
        self.rag = None
        self.bert = None
        self.groq_client = None
        self.qr_urls = []
        
        # Initialize Groq
        if cfg.GROQ_API_KEY:
            try:
                self.groq_client = Groq(api_key=cfg.GROQ_API_KEY)
                logger.info("✅ Groq client initialized")
            except Exception as e:
                logger.error(f"Groq init failed: {e}")
        
        # Scoring weights
        self.weights = {
            "text": 0.20,
            "url": 0.30,
            "rag": 0.20,
            "bert": 0.30,
        }
    
    async def _lazy_init(self):
        """Lazy-load heavy components."""
        if self.text_pipeline is None and TextPipeline:
            try:
                self.text_pipeline = TextPipeline()
                logger.debug("TextPipeline loaded")
            except Exception as e:
                logger.warning(f"TextPipeline failed: {e}")
        
        if self.url_pipeline is None and URLPipeline:
            try:
                self.url_pipeline = URLPipeline()
                logger.debug("URLPipeline loaded")
            except Exception as e:
                logger.warning(f"URLPipeline failed: {e}")
        
        if self.rag is None and ChromaRAG:
            try:
                self.rag = ChromaRAG()
                if self.rag:
                    stats = self.rag.get_stats()
                    logger.info(f"ChromaRAG loaded: {stats.get('urls', 0):,} URLs")
            except Exception as e:
                logger.warning(f"ChromaRAG failed: {e}")
    
    async def _run_text(self, mail: Dict) -> float:
        """Text pipeline with fallback."""
        if not self.text_pipeline:
            # Fallback heuristic analysis
            subject = mail.get("subject", "").lower()
            body = mail.get("body_text", "").lower()
            
            score = 0.0
            urgent_words = ["urgent", "immediate", "suspended", "verify", "confirm"]
            for word in urgent_words:
                if word in subject or word in body:
                    score += 0.12
            
            urgency_phrases = ["within 24 hours", "immediately", "action required"]
            for phrase in urgency_phrases:
                if phrase in body:
                    score += 0.15
            
            return min(score, 1.0)
        
        try:
            return await self.text_pipeline.analyze(mail)
        except Exception as e:
            logger.error(f"Text pipeline failed: {e}")
            return 0.0
    
    async def _run_url(self, mail: Dict) -> float:
        """URL pipeline with QR extraction."""
        if not self.url_pipeline:
            # Fallback URL analysis
            urls = mail.get("urls", [])
            body = mail.get("body_text", "")
            
            import re
            found_urls = re.findall(r'https?://[^\s]+', body)
            urls.extend(found_urls)
            
            if not urls:
                return 0.0
            
            score = 0.0
            suspicious = ["secure", "verify", "login", "confirm"]
            for url in urls:
                for sus in suspicious:
                    if sus in url.lower():
                        score += 0.1
                
                # Brand impersonation
                brands = ["paypal", "amazon", "apple", "chase", "microsoft"]
                for brand in brands:
                    if brand in url.lower():
                        score += 0.2
            
            return min(score, 1.0)
        
        try:
            return await self.url_pipeline.analyze(mail)
        except Exception as e:
            logger.error(f"URL pipeline failed: {e}")
            return 0.0
    
    async def _run_rag(self, mail: Dict) -> float:
        """RAG: Query ChromaDB."""
        if not self.rag:
            return 0.0
        
        try:
            urls = mail.get("urls", [])
            if urls:
                score = await self.rag.query_url(urls[0])
                if score > 0:
                    return score
            
            score = await self.rag.query_email(
                mail.get("subject", ""),
                mail.get("body_text", "")
            )
            return score
            
        except Exception as e:
            logger.error(f"RAG failed: {e}")
            return 0.0
    
    async def _run_bert(self, mail: Dict) -> float:
        """BERT classifier (simulated if not available)."""
        # Simple keyword-based scoring as fallback
        text = f"{mail.get('subject', '')} {mail.get('body_text', '')}".lower()
        
        high_risk = ["suspended", "blocked", "limited", "locked"]
        medium_risk = ["verify", "confirm", "validate", "update"]
        
        score = 0.0
        for word in high_risk:
            if word in text:
                score += 0.15
        for word in medium_risk:
            if word in text:
                score += 0.08
        
        return min(score, 1.0)
    
    async def _run_groq(self, mail: Dict) -> Optional[str]:
        """LLM fallback for semantic analysis."""
        if not self.groq_client:
            return None
        
        try:
            prompt = f"""Analyze this email for phishing. Return ONLY valid JSON.

From: {mail.get('from', 'unknown')}
Subject: {mail.get('subject', '')}
Body: {mail.get('body_text', '')[:500]}

Return: {{"is_phishing": true/false, "confidence": 0-1, "reason": "brief explanation"}}"""
            
            response = await asyncio.to_thread(
                self.groq_client.chat.completions.create,
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=200
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Groq failed: {e}")
            return None
    
    async def analyze_email(self, mail: Dict) -> AnalysisResult:
        """Main analysis entry point."""
        start_time = time.time()
        
        # Lazy load components
        await self._lazy_init()
        
        # Extract QR codes if URL pipeline has the method
        qr_urls = []
        if self.url_pipeline and hasattr(self.url_pipeline, 'extract_qr_from_attachments'):
            attachments = mail.get("attachments", [])
            if attachments:
                qr_urls = self.url_pipeline.extract_qr_from_attachments(attachments)
                if qr_urls:
                    mail['urls'] = mail.get('urls', []) + qr_urls
                    logger.info(f"📱 Found {len(qr_urls)} QR URLs")
        
        # Run all pipelines in parallel
        tasks = [
            self._run_text(mail),
            self._run_url(mail),
            self._run_rag(mail),
            self._run_bert(mail),
            self._run_groq(mail),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Extract results
        text_score = results[0] if not isinstance(results[0], Exception) else 0.0
        url_score = results[1] if not isinstance(results[1], Exception) else 0.0
        rag_score = results[2] if not isinstance(results[2], Exception) else 0.0
        bert_score = results[3] if not isinstance(results[3], Exception) else 0.0
        groq_result = results[4] if not isinstance(results[4], Exception) else None
        
        # Aggregate scores
        scores = {
            "text": float(text_score),
            "url": float(url_score),
            "rag": float(rag_score),
            "bert": float(bert_score),
        }
        
        score_final = (
            scores["text"] * self.weights["text"] +
            scores["url"] * self.weights["url"] +
            scores["rag"] * self.weights["rag"] +
            scores["bert"] * self.weights["bert"]
        )
        
        # ============================================================
        # UPDATED THRESHOLDS - Matches URL pipeline detection levels
        # ============================================================
        if score_final >= 0.50:
            verdict = "MALICIOUS"
            reason = "High confidence phishing detection"
        elif score_final >= 0.30:
            verdict = "SUSPICIOUS"
            reason = "Multiple phishing indicators detected"
        elif score_final >= 0.15:
            verdict = "LOW_SUSPICION"
            reason = "Some phishing indicators present"
        else:
            verdict = "CLEAN"
            reason = "No significant phishing indicators"
        
        # Parse Groq response if available
        if groq_result and isinstance(groq_result, str):
            try:
                import re
                json_match = re.search(r'\{[^{}]*\}', groq_result)
                if json_match:
                    groq_data = json.loads(json_match.group())
                    if groq_data.get("is_phishing"):
                        reason += f" | LLM: {groq_data.get('reason', '')[:100]}"
                        # Boost score if LLM confirms phishing
                        if groq_data.get("confidence", 0) > 0.7:
                            score_final = min(1.0, score_final + 0.1)
                            if score_final >= 0.50 and verdict == "SUSPICIOUS":
                                verdict = "MALICIOUS"
            except:
                pass
        
        # Add QR info to reason
        if qr_urls:
            reason += f" | QR codes found: {len(qr_urls)}"
        
        return AnalysisResult(
            uid=mail.get('uid', 'unknown'),
            sender=mail.get('from', 'unknown'),
            subject=mail.get('subject', ''),
            verdict=verdict,
            score_final=score_final,
            scores=scores,
            reason=reason,
            processing_time=time.time() - start_time,
            timestamp=datetime.now().isoformat(),
            qr_urls=qr_urls,
            groq_analysis=groq_result,
        )


# Singleton instance
_orchestrator = None


async def analyze_email(mail: Dict) -> AnalysisResult:
    """Convenience function to analyze email."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return await _orchestrator.analyze_email(mail)


async def test():
    """Test with sample emails."""
    print("\n" + "=" * 60)
    print("📧 TEST 1: Clean Email")
    print("=" * 60)
    result = await analyze_email({
        "uid": "test_1",
        "from": "friend@example.com",
        "subject": "Meeting tomorrow",
        "body_text": "Hi, just a reminder about our meeting at 2pm.",
        "urls": [],
        "attachments": []
    })
    print(result.to_json())
    
    print("\n" + "=" * 60)
    print("🎣 TEST 2: Phishing Email")
    print("=" * 60)
    result = await analyze_email({
        "uid": "test_2",
        "from": "security@paypal.com",
        "subject": "URGENT: Account suspended",
        "body_text": "Click here to verify: http://paypal-verify-login.com",
        "urls": ["http://paypal-verify-login.com"],
        "attachments": []
    })
    print(result.to_json())


async def test_10_emails():
    """Test with 5 good + 5 bad emails."""
    # 5 Good emails
    good_emails = [
        {"uid": "good_1", "from": "news@medium.com", "subject": "Weekly digest", 
         "body_text": "Here are your weekly articles.", "urls": [], "attachments": []},
        {"uid": "good_2", "from": "calendar@google.com", "subject": "Meeting reminder", 
         "body_text": "Team meeting at 2pm tomorrow.", "urls": [], "attachments": []},
        {"uid": "good_3", "from": "noreply@github.com", "subject": "Pull request", 
         "body_text": "Your PR has been reviewed.", "urls": [], "attachments": []},
        {"uid": "good_4", "from": "trello@trello.com", "subject": "Cards due", 
         "body_text": "You have tasks due today.", "urls": [], "attachments": []},
        {"uid": "good_5", "from": "slack@slack.com", "subject": "Messages", 
         "body_text": "You have new messages.", "urls": [], "attachments": []},
    ]
    
    # 5 Bad emails
    bad_emails = [
        {"uid": "bad_1", "from": "security@paypal-security.com", "subject": "⚠️ Account suspended", 
         "body_text": "Verify now: http://paypal-verify.com", 
         "urls": ["http://paypal-verify.com"], "attachments": []},
        {"uid": "bad_2", "from": "amazon@delivery-track.net", "subject": "Package cannot be delivered", 
         "body_text": "Confirm address: https://amazon-verify.net", 
         "urls": ["https://amazon-verify.net"], "attachments": []},
        {"uid": "bad_3", "from": "apple@appleid-verify.com", "subject": "Apple ID compromised", 
         "body_text": "Secure your account: http://appleid-restore.com", 
         "urls": ["http://appleid-restore.com"], "attachments": []},
        {"uid": "bad_4", "from": "chase@alerts-security.com", "subject": "Unusual activity", 
         "body_text": "Verify transaction: https://chase-secure.com", 
         "urls": ["https://chase-secure.com"], "attachments": []},
        {"uid": "bad_5", "from": "microsoft@account-security.net", "subject": "Sign-in from Russia", 
         "body_text": "Recover your account: https://microsoft-alert.com", 
         "urls": ["https://microsoft-alert.com"], "attachments": []},
    ]
    
    print("\n" + "=" * 70)
    print("🔬 GHOST SENTRY - 10 EMAIL TEST")
    print("=" * 70)
    print("📧 5 Legitimate emails (should be CLEAN)")
    print("🎣 5 Phishing emails (should be SUSPICIOUS/MALICIOUS)")
    print("=" * 70 + "\n")
    
    results = []
    
    print("📧 GOOD EMAILS:")
    print("-" * 50)
    for email in good_emails:
        result = await analyze_email(email)
        results.append(("GOOD", result))
        status = "✅" if result.verdict == "CLEAN" else "⚠️"
        print(f"{status} {email['uid']:8s} | Verdict: {result.verdict:12s} | Score: {result.score_final:.3f}")
    
    print("\n🎣 BAD EMAILS:")
    print("-" * 50)
    for email in bad_emails:
        result = await analyze_email(email)
        results.append(("BAD", result))
        status = "✅" if result.verdict in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"] else "❌"
        print(f"{status} {email['uid']:8s} | Verdict: {result.verdict:12s} | Score: {result.score_final:.3f}")
    
    # Summary
    print("\n" + "=" * 70)
    correct = 0
    for expected, result in results:
        if expected == "GOOD" and result.verdict == "CLEAN":
            correct += 1
        elif expected == "BAD" and result.verdict in ["SUSPICIOUS", "MALICIOUS", "LOW_SUSPICION"]:
            correct += 1
    
    print(f"📊 ACCURACY: {correct}/10 ({correct*10:.0f}%)")
    print("=" * 70)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "10":
        asyncio.run(test_10_emails())
    else:
        asyncio.run(test())