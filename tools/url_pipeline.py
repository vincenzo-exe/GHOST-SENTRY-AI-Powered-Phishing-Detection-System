"""
tools/url_pipeline.py — URL Analysis Pipeline for Ghost Sentry
Step 3: Analyze URLs for phishing indicators + QR code extraction
"""

import logging
import re
import io
import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from datetime import datetime
import socket

import aiohttp
import tldextract
from PIL import Image
from pyzbar.pyzbar import decode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLPipeline:
    """
    URL Analysis Pipeline for Ghost Sentry.
    Analyzes URLs for phishing indicators including:
    - Typosquatting detection
    - Brand impersonation
    - Suspicious TLDs
    - URL length and structure
    - QR code extraction from images
    """
    
    def __init__(self):
        """Initialize URL Pipeline."""
        # Brands commonly targeted by phishing
        self.brands = {
            "paypal": ["paypal.com", "paypal.com.br", "paypal.co.uk"],
            "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr"],
            "apple": ["apple.com", "icloud.com"],
            "microsoft": ["microsoft.com", "live.com", "outlook.com"],
            "google": ["google.com", "gmail.com", "youtube.com"],
            "facebook": ["facebook.com", "fb.com"],
            "instagram": ["instagram.com"],
            "linkedin": ["linkedin.com"],
            "chase": ["chase.com"],
            "wellsfargo": ["wellsfargo.com"],
            "bankofamerica": ["bankofamerica.com"],
            "dropbox": ["dropbox.com"],
            "netflix": ["netflix.com"],
            "spotify": ["spotify.com"],
            "adobe": ["adobe.com"],
        }
        
        # Suspicious TLDs (commonly used in phishing)
        self.suspicious_tlds = [
            "tk", "ml", "ga", "cf", "xyz", "top", "club", "online", 
            "site", "website", "space", "tech", "store", "shop"
        ]
        
        # Suspicious words in URLs
        self.suspicious_words = [
            "secure", "verify", "login", "signin", "account", "update",
            "confirm", "validate", "authenticate", "security", "alert",
            "suspended", "blocked", "limited", "restricted", "unusual",
            "activity", "transaction", "payment", "billing", "invoice"
        ]
        
        # Session for HTTP requests
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self.session is None:
            self.session = aiohttp.ClientSession()
        return self.session
    
    def extract_urls_from_text(self, text: str) -> List[str]:
        """
        Extract URLs from text using regex.
        
        Args:
            text: Text to extract URLs from
        
        Returns:
            List of unique URLs found
        """
        if not text:
            return []
        
        # URL regex pattern
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s)\]}]*)?'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        
        # Clean up and remove duplicates
        clean_urls = []
        for url in urls:
            # Remove trailing punctuation
            url = url.rstrip('.,;:!?)\']')
            if url.startswith(('http://', 'https://')):
                clean_urls.append(url.lower())
        
        return list(set(clean_urls))
    
    def extract_qr_from_attachments(self, attachments: List[Dict]) -> List[str]:
        """
        Extract URLs from QR codes in image attachments.
        
        Args:
            attachments: List of attachment dicts with 'data' and 'content_type'
        
        Returns:
            List of URLs found in QR codes
        """
        qr_urls = []
        
        if not attachments:
            return qr_urls
        
        for att in attachments:
            # Check if it's an image
            content_type = att.get("content_type", "").lower()
            if not content_type.startswith("image/"):
                continue
            
            image_data = att.get("data")
            if not image_data:
                continue
            
            filename = att.get("filename", "unknown")
            
            try:
                # Open image from bytes
                img = Image.open(io.BytesIO(image_data))
                
                # Decode QR codes and barcodes
                decoded_objects = decode(img)
                
                for obj in decoded_objects:
                    data = obj.data.decode('utf-8')
                    
                    # Check if it's a URL
                    if data.startswith(("http://", "https://")):
                        qr_urls.append(data)
                        logger.info(f"📱 QR URL extracted from {filename}: {data[:60]}...")
                    elif data.startswith(("ftp://", "file://")):
                        logger.warning(f"⚠️ Suspicious QR protocol in {filename}: {data[:50]}")
                        qr_urls.append(data)
                        
            except Exception as e:
                logger.debug(f"QR decode failed for {filename}: {e}")
        
        if qr_urls:
            logger.info(f"✅ Extracted {len(qr_urls)} URLs from QR codes")
        
        return qr_urls
    
    def analyze_url_structure(self, url: str) -> float:
        """
        Analyze URL structure for phishing indicators.
        Returns score from 0-1 (higher = more suspicious)
        """
        score = 0.0
        url_lower = url.lower()
        
        try:
            parsed = urlparse(url_lower)
            domain = parsed.netloc
            path = parsed.path
            query = parsed.query
            
            # Check for IP address instead of domain (HIGH RISK)
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, domain):
                score += 0.60  # Much higher weight for IP addresses
                logger.debug(f"IP address domain: {domain}")
            
            # Check for excessive subdomains (phishing uses many subdomains)
            subdomain_count = domain.count('.')
            if subdomain_count > 2:
                score += min(0.35, (subdomain_count - 2) * 0.12)
            
            # Check for very long URLs (phishing often has long URLs)
            if len(url) > 100:
                score += 0.15
            if len(url) > 150:
                score += 0.10
            if len(url) > 200:
                score += 0.10
            
            # Check for suspicious characters
            if '@' in domain:
                score += 0.30  # @ in domain is very suspicious
            
            # Hyphens in domain (legit domains rarely have hyphens)
            if domain.count('-') > 1:
                score += 0.15
            
            # Check for suspicious paths with keywords
            suspicious_in_path = 0
            for word in self.suspicious_words:
                if word in path.lower() or word in query.lower():
                    suspicious_in_path += 0.08
            
            score += min(0.40, suspicious_in_path)
            
            # Check for multiple slashes (redirect tricks)
            if path.count('//') > 1:
                score += 0.15
            
            # Check for URL encoding
            if '%' in url:
                score += 0.10
            
            # Check for numeric domains (e.g., 12345.com)
            if re.search(r'^\d+\.', domain):
                score += 0.25
                
        except Exception as e:
            logger.debug(f"URL structure analysis failed: {e}")
        
        return min(score, 1.0)
    
    def detect_typosquatting(self, url: str) -> float:
        """
        Detect typosquatting and brand impersonation.
        Returns score from 0-1 (higher = more suspicious)
        """
        score = 0.0
        url_lower = url.lower()
        
        try:
            parsed = urlparse(url_lower)
            domain = parsed.netloc
            
            # Remove www prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check each brand
            for brand, legit_domains in self.brands.items():
                if brand in url_lower:
                    # Check if it's actually the real domain
                    is_legit = False
                    for legit in legit_domains:
                        if domain == legit or domain.endswith('.' + legit):
                            is_legit = True
                            break
                    
                    if not is_legit:
                        # Brand impersonation detected - HIGH RISK
                        score += 0.55
                        logger.debug(f"Brand impersonation: {brand} in {domain}")
                        
                        # Extra points for specific suspicious patterns
                        # Check for "secure", "verify" etc with brand
                        for sus in self.suspicious_words:
                            if sus in url_lower:
                                score += 0.10
                                break
                        
                        # Check if domain is completely different (not a subdomain)
                        if brand not in domain.replace('-', ''):
                            score += 0.15
                        
                        break
            
            # Check for suspicious TLDs
            ext = tldextract.extract(url_lower)
            if ext.suffix in self.suspicious_tlds:
                score += 0.30
                logger.debug(f"Suspicious TLD: .{ext.suffix}")
            
            # Check for homoglyph patterns
            homoglyph_patterns = [
                ('rn', 'm'),      # rn -> m (paypal -> paypal)
                ('vv', 'w'),      # vv -> w
                ('0', 'o'),       # 0 -> o
                ('1', 'l'),       # 1 -> l
                ('5', 's'),       # 5 -> s
                ('rn', 'm'),      # rn -> m
            ]
            
            for pattern, replacement in homoglyph_patterns:
                if pattern in domain:
                    test_domain = domain.replace(pattern, replacement)
                    for brand in self.brands.keys():
                        if brand in test_domain:
                            score += 0.25
                            break
            
            # Check for brand name with extra characters (paypal-login.com)
            for brand in self.brands.keys():
                if brand + '-' in url_lower or brand + '_' in url_lower:
                    score += 0.35
                    break
            
            # Check for "secure", "verify" in domain (common in phishing)
            if any(word in domain for word in ['secure', 'verify', 'login', 'signin']):
                score += 0.20
                
        except Exception as e:
            logger.debug(f"Typosquatting detection failed: {e}")
        
        return min(score, 1.0)
    
    async def check_url_reputation(self, url: str) -> float:
        """
        Check URL reputation.
        Returns score from 0-1 (higher = more suspicious)
        """
        score = 0.0
        
        try:
            # Check for URL shorteners (often used in phishing)
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 
                         'is.gd', 'buff.ly', 't.co', 'short.link',
                         'shorturl.at', 'cutt.ly', 'rebrand.ly']
            
            for shortener in shorteners:
                if shortener in url.lower():
                    score += 0.35
                    logger.debug(f"Short URL detected: {shortener}")
                    break
            
            # Check for suspicious numeric redirects
            if 'redirect' in url.lower() or 'redir' in url.lower():
                score += 0.20
            
            # Optional: Check if domain resolves
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, socket.gethostbyname, domain)
            except:
                score += 0.15  # Domain doesn't resolve
                logger.debug(f"Domain does not resolve: {domain}")
                
        except Exception as e:
            logger.debug(f"Reputation check failed: {e}")
        
        return min(score, 1.0)
    
    async def analyze_url(self, url: str) -> float:
        """
        Complete URL analysis returning a score from 0-1.
        Higher score = more likely to be phishing.
        
        Args:
            url: URL to analyze
        
        Returns:
            Score from 0 (safe) to 1 (malicious)
        """
        if not url:
            return 0.0
        
        # Run all analyses
        structure_score = self.analyze_url_structure(url)
        typosquatting_score = self.detect_typosquatting(url)
        reputation_score = await self.check_url_reputation(url)
        
        # Weighted combination
        final_score = (
            structure_score * 0.30 +
            typosquatting_score * 0.50 +
            reputation_score * 0.20
        )
        
        logger.debug(f"URL analysis: {url[:60]}... = {final_score:.3f}")
        
        return final_score
    
    async def analyze(self, mail: Dict) -> float:
        """
        Analyze all URLs in an email including body text and QR codes.
        Returns the maximum score from all URLs found.
        
        Args:
            mail: Email dict with keys: body_text, urls, attachments
        
        Returns:
            Maximum suspicion score from all URLs (0-1)
        """
        all_urls = []
        
        # 1. Extract URLs from email body
        body_text = mail.get("body_text", "") or mail.get("body", "") or mail.get("text", "")
        if body_text:
            text_urls = self.extract_urls_from_text(body_text)
            all_urls.extend(text_urls)
            if text_urls:
                logger.debug(f"Found {len(text_urls)} URLs in email body")
        
        # 2. Extract URLs from explicit urls field
        explicit_urls = mail.get("urls", [])
        all_urls.extend(explicit_urls)
        
        # 3. Extract URLs from QR codes in attachments
        attachments = mail.get("attachments", [])
        if attachments:
            qr_urls = self.extract_qr_from_attachments(attachments)
            all_urls.extend(qr_urls)
            if qr_urls:
                logger.info(f"Found {len(qr_urls)} QR code URLs")
        
        # Remove duplicates
        all_urls = list(set(all_urls))
        
        if not all_urls:
            logger.debug("No URLs found in email")
            return 0.0
        
        # Analyze each URL and take the highest score
        max_score = 0.0
        for url in all_urls:
            score = await self.analyze_url(url)
            if score > max_score:
                max_score = score
        
        logger.info(f"URL analysis complete: {len(all_urls)} URLs, max score={max_score:.3f}")
        return max_score
    
    async def close(self):
        """Close aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None


# Test function
async def test():
    """Test the URL pipeline with detailed breakdown."""
    pipeline = URLPipeline()
    
    print("\n" + "=" * 70)
    print("🔗 URL Pipeline Test - Detailed Breakdown")
    print("=" * 70)
    
    test_urls = [
        ("https://google.com", "Legitimate - real Google"),
        ("http://paypal-secure-login.com", "Phishing - typosquatting"),
        ("https://amazon-verify-account.net", "Phishing - brand impersonation"),
        ("http://appleid-restore.com", "Phishing - suspicious domain"),
        ("https://chase-secure-verify.com/login", "Phishing - multiple indicators"),
        ("http://192.168.1.1/paypal/login", "Phishing - IP address"),
        ("https://paypal.com", "Legitimate - real PayPal"),
        ("https://www.amazon.com/gp/help", "Legitimate - real Amazon"),
    ]
    
    print("\n📊 URL Analysis Results:")
    print("-" * 80)
    
    results = []
    for url, description in test_urls:
        structure = pipeline.analyze_url_structure(url)
        typosquatting = pipeline.detect_typosquatting(url)
        reputation = await pipeline.check_url_reputation(url)
        
        # Weighted combination (matches analyze_url)
        final_score = (structure * 0.30) + (typosquatting * 0.50) + (reputation * 0.20)
        
        # Classification with adjusted thresholds
        if final_score >= 0.50:
            classification = "🔴 MALICIOUS"
            threat_level = "HIGH"
        elif final_score >= 0.30:
            classification = "🟡 SUSPICIOUS"
            threat_level = "MEDIUM"
        elif final_score >= 0.15:
            classification = "� LOW_SUSPICION"
            threat_level = "LOW"
        else:
            classification = "🟢 CLEAN"
            threat_level = "NONE"
        
        results.append((url, final_score, classification, threat_level, description))
        
        print(f"\n{classification}")
        print(f"   URL: {url[:65]}")
        print(f"   Structure: {structure:.3f} + Typosquatting: {typosquatting:.3f} + Reputation: {reputation:.3f}")
        print(f"   Final Score: {final_score:.3f} ({threat_level} threat)")
        print(f"   Expected: {description}")
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    
    print("\nThresholds for classification:")
    print("   🔴 MALICIOUS:      score >= 0.50")
    print("   🟡 SUSPICIOUS:     score >= 0.30")
    print("   🟠 LOW_SUSPICION:  score >= 0.15")
    print("   🟢 CLEAN:          score < 0.15")
    
    print("\nRecommendation: Update orchestrator.py thresholds to match these values")
    
    await pipeline.close()


if __name__ == "__main__":
    asyncio.run(test())