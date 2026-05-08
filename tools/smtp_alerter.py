"""
smtp_alerter.py — Send email alerts for detected phishing emails
"""

import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional
from config.settings import Settings

logger = logging.getLogger(__name__)


class SMTPAlerter:
    """Send SMTP alerts for malicious emails detected."""
    
    def __init__(self):
        """Initialize SMTP alerter from settings."""
        self.cfg = Settings()
        self.smtp_host = self.cfg.SMTP_HOST
        self.smtp_port = self.cfg.SMTP_PORT
        self.smtp_user = self.cfg.SMTP_USER
        self.smtp_password = self.cfg.SMTP_PASSWORD
        self.alert_recipient = self.cfg.ALERT_RECIPIENT
        self.alert_sender = self.cfg.ALERT_SENDER or self.smtp_user
        
        if not all([self.smtp_host, self.smtp_user, self.smtp_password, self.alert_recipient]):
            logger.warning("⚠️  SMTP configuration incomplete - alerts disabled")
            self.enabled = False
        else:
            self.enabled = True
            logger.info("✅ SMTPAlerter initialized")
    
    async def alert_malicious(self, result: Dict) -> bool:
        """
        Send email alert for MALICIOUS verdict.
        
        Args:
            result: AnalysisResult.to_dict() with analysis details
            
        Returns:
            True if alert sent successfully, False otherwise
        """
        if not self.enabled:
            logger.debug("SMTP alerter disabled - skipping alert")
            return False
        
        try:
            # Build email
            subject = f"🔴 PHISHING ALERT - {result.get('subject', 'Unknown')}"
            
            body_html = self._build_html_alert(result)
            body_text = self._build_text_alert(result)
            
            # Send in background
            await asyncio.to_thread(
                self._send_smtp,
                self.alert_sender,
                self.alert_recipient,
                subject,
                body_text,
                body_html
            )
            
            logger.info(f"✅ Alert sent for UID={result.get('uid')}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send alert: {e}")
            return False
    
    def _send_smtp(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body_text: str,
        body_html: str
    ) -> None:
        """Send email via SMTP (blocking operation)."""
        try:
            # Create MIME message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = recipient
            
            # Attach text and HTML versions
            part_text = MIMEText(body_text, "plain")
            part_html = MIMEText(body_html, "html")
            msg.attach(part_text)
            msg.attach(part_html)
            
            # Connect and send
            if self.smtp_port == 587:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=10)
            
            server.login(self.smtp_user, self.smtp_password)
            server.sendmail(sender, recipient, msg.as_string())
            server.quit()
            
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            raise
    
    def _build_html_alert(self, result: Dict) -> str:
        """Build HTML formatted alert email."""
        return f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; background-color: #f5f5f5; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
                    .header {{ background: #d32f2f; color: white; padding: 15px; border-radius: 4px; text-align: center; }}
                    .section {{ margin: 15px 0; padding: 10px; background: #f9f9f9; border-left: 4px solid #d32f2f; }}
                    .field {{ margin: 8px 0; }}
                    .label {{ font-weight: bold; color: #333; }}
                    .value {{ color: #555; word-break: break-word; }}
                    .scores {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 10px 0; }}
                    .score-item {{ padding: 10px; background: white; border-radius: 4px; }}
                    .high {{ color: #d32f2f; font-weight: bold; }}
                    .button {{ display: inline-block; padding: 10px 20px; background: #d32f2f; color: white; text-decoration: none; border-radius: 4px; margin: 10px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔴 PHISHING ALERT</h1>
                        <p>Malicious email detected by Ghost Sentry</p>
                    </div>
                    
                    <div class="section">
                        <div class="field">
                            <span class="label">UID:</span>
                            <span class="value">{result.get('uid', 'N/A')}</span>
                        </div>
                        <div class="field">
                            <span class="label">From:</span>
                            <span class="value">{result.get('sender', 'N/A')}</span>
                        </div>
                        <div class="field">
                            <span class="label">Subject:</span>
                            <span class="value">{result.get('subject', 'N/A')}</span>
                        </div>
                        <div class="field">
                            <span class="label">Timestamp:</span>
                            <span class="value">{result.get('timestamp', 'N/A')}</span>
                        </div>
                    </div>
                    
                    <div class="section">
                        <div class="field">
                            <span class="label">Verdict:</span>
                            <span class="value high">{result.get('verdict', 'N/A')}</span>
                        </div>
                        <div class="field">
                            <span class="label">Final Score:</span>
                            <span class="value high">{result.get('score_final', 0):.4f}</span>
                        </div>
                        <div class="field">
                            <span class="label">Reason:</span>
                            <span class="value">{result.get('reason', 'N/A')}</span>
                        </div>
                    </div>
                    
                    <div class="section">
                        <span class="label">Analysis Scores:</span>
                        <div class="scores">
                            <div class="score-item">
                                <strong>Text:</strong><br/>
                                {result.get('scores', {}).get('text', 0):.3f}
                            </div>
                            <div class="score-item">
                                <strong>URL:</strong><br/>
                                {result.get('scores', {}).get('url', 0):.3f}
                            </div>
                            <div class="score-item">
                                <strong>RAG:</strong><br/>
                                {result.get('scores', {}).get('rag', 0):.3f}
                            </div>
                            <div class="score-item">
                                <strong>BERT:</strong><br/>
                                {result.get('scores', {}).get('bert', 0):.3f}
                            </div>
                        </div>
                    </div>
                    
                    {'<div class="section"><span class="label">QR URLs Detected:</span><div>' + 
                     '<br/>'.join([f'<span class="value">• {url}</span>' for url in result.get('qr_urls', [])]) + 
                     '</div></div>' if result.get('qr_urls') else ''}
                    
                    <div class="section" style="text-align: center; background: #fff3cd; border-left-color: #ff9800;">
                        <p><strong>⚠️ ACTION REQUIRED</strong></p>
                        <p>Review this email immediately and take appropriate action.</p>
                        <p style="font-size: 12px; color: #666;">Processing time: {result.get('processing_time_ms', 0):.2f}ms</p>
                    </div>
                </div>
            </body>
        </html>
        """
    
    def _build_text_alert(self, result: Dict) -> str:
        """Build plain text formatted alert email."""
        qr_section = ""
        if result.get('qr_urls'):
            qr_section = "\nQR URLs Detected:\n" + "\n".join(
                [f"  • {url}" for url in result.get('qr_urls', [])]
            )
        
        return f"""
PHISHING ALERT — Ghost Sentry
================================

UID: {result.get('uid', 'N/A')}
From: {result.get('sender', 'N/A')}
Subject: {result.get('subject', 'N/A')}
Timestamp: {result.get('timestamp', 'N/A')}

VERDICT: {result.get('verdict', 'N/A')} (Score: {result.get('score_final', 0):.4f})
Reason: {result.get('reason', 'N/A')}

Analysis Breakdown:
  • Text Score: {result.get('scores', {}).get('text', 0):.3f}
  • URL Score: {result.get('scores', {}).get('url', 0):.3f}
  • RAG Score: {result.get('scores', {}).get('rag', 0):.3f}
  • BERT Score: {result.get('scores', {}).get('bert', 0):.3f}

{qr_section}

Processing Time: {result.get('processing_time_ms', 0):.2f}ms

⚠️  ACTION REQUIRED
Review this email immediately and take appropriate action.

---
Ghost Sentry Phishing Detection System
        """.strip()
    
    async def alert_suspicious(self, result: Dict) -> bool:
        """
        Send email alert for SUSPICIOUS verdict (optional).
        
        Args:
            result: AnalysisResult.to_dict() with analysis details
            
        Returns:
            True if alert sent successfully, False otherwise
        """
        if not self.enabled:
            return False
        
        try:
            subject = f"🟡 SUSPICIOUS EMAIL - {result.get('subject', 'Unknown')}"
            body_text = self._build_text_alert(result)
            
            await asyncio.to_thread(
                self._send_smtp,
                self.alert_sender,
                self.alert_recipient,
                subject,
                body_text,
                self._build_html_alert(result)
            )
            
            logger.info(f"✅ Suspicious alert sent for UID={result.get('uid')}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send suspicious alert: {e}")
            return False
