"""
tools/qr_extractor.py — QR Code Extraction from Email Attachments
Step 3: Extract phishing URLs from QR codes in images
"""

import logging
import io
from typing import List, Dict, Optional
from pathlib import Path

from PIL import Image
from pyzbar.pyzbar import decode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QRExtractor:
    """Extract URLs from QR codes in email attachments."""
    
    def __init__(self):
        self.stats = {"total_images": 0, "qrs_found": 0, "urls_extracted": 0}
    
    def extract_from_bytes(self, image_bytes: bytes, filename: str = "unknown") -> List[str]:
        """
        Extract URLs from QR codes in image bytes.
        
        Args:
            image_bytes: Raw image data from attachment
            filename: Original filename for logging
        
        Returns:
            List of extracted URLs (only http/https)
        """
        urls = []
        
        try:
            # Open image from bytes
            img = Image.open(io.BytesIO(image_bytes))
            self.stats["total_images"] += 1
            
            # Decode all barcodes/QR codes
            decoded_objects = decode(img)
            
            for obj in decoded_objects:
                data = obj.data.decode('utf-8')
                
                # Check if it's a URL
                if data.startswith(("http://", "https://")):
                    urls.append(data)
                    self.stats["qrs_found"] += 1
                    self.stats["urls_extracted"] += 1
                    logger.info(f"QR URL found in {filename}: {data[:50]}...")
                elif data.startswith(("ftp://", "file://")):
                    # Warn about suspicious protocols
                    logger.warning(f"Suspicious QR protocol in {filename}: {data[:50]}")
                    urls.append(data)  # Still extract for analysis
            
            return urls
            
        except Exception as e:
            logger.debug(f"QR extraction failed for {filename}: {e}")
            return []
    
    def extract_from_attachment(self, attachment: Dict) -> List[str]:
        """
        Extract from attachment dict (from mail_listener.py format).
        
        Expected format:
        {
            "filename": "image.png",
            "content_type": "image/png",
            "data": b"...",
            "size": 1234
        }
        """
        # Check if it's an image
        content_type = attachment.get("content_type", "").lower()
        if not content_type.startswith("image/"):
            return []
        
        image_bytes = attachment.get("data")
        filename = attachment.get("filename", "unknown")
        
        if not image_bytes:
            return []
        
        return self.extract_from_bytes(image_bytes, filename)
    
    def extract_from_email(self, email_data: Dict) -> List[str]:
        """
        Extract QR URLs from all attachments in an email.
        
        Args:
            email_data: Email dict with 'attachments' key
        
        Returns:
            List of all URLs found in QR codes
        """
        all_urls = []
        attachments = email_data.get("attachments", [])
        
        for att in attachments:
            urls = self.extract_from_attachment(att)
            all_urls.extend(urls)
        
        if all_urls:
            logger.info(f"Extracted {len(all_urls)} QR URLs from email")
        
        return all_urls
    
    def get_stats(self) -> Dict:
        """Return extraction statistics."""
        return self.stats.copy()
    
    def reset_stats(self):
        """Reset statistics counter."""
        self.stats = {"total_images": 0, "qrs_found": 0, "urls_extracted": 0}


# Integration with URL Pipeline
class QRIntegration:
    """Helper to integrate QR extraction into url_pipeline.py"""
    
    @staticmethod
    async def extract_and_analyze(email_data: Dict, url_pipeline) -> List[Dict]:
        """
        Extract QR URLs and analyze them through URL pipeline.
        
        Args:
            email_data: Email dict
            url_pipeline: URLPipeline instance
        
        Returns:
            List of URL analysis results
        """
        extractor = QRExtractor()
        qr_urls = extractor.extract_from_email(email_data)
        
        results = []
        for url in qr_urls:
            # Analyze each QR URL
            analysis = await url_pipeline.analyze_url(url)
            results.append({
                "url": url,
                "source": "qr_code",
                "analysis": analysis
            })
        
        return results


# Test function
def test_qr_extractor():
    """Test with sample QR code image."""
    import os
    
    extractor = QRExtractor()
    
    # Check if test image exists
    test_image = Path("test_qr.png")
    
    if test_image.exists():
        with open(test_image, "rb") as f:
            image_bytes = f.read()
        
        urls = extractor.extract_from_bytes(image_bytes, "test_qr.png")
        print(f"Extracted URLs: {urls}")
    else:
        print("No test image found. Create one with:")
        print("  qrencode -o test_qr.png 'https://paypal-phishing.com/login'")
    
    print(f"Stats: {extractor.get_stats()}")


if __name__ == "__main__":
    test_qr_extractor()