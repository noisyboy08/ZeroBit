"""
Email alerting for ZeroBit security incidents.
Sends high-priority alerts via email with context and remediation advice.
"""

from __future__ import annotations

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional, List


class EmailAlerter:
    """Sends security alerts via email."""

    def __init__(
        self,
        smtp_server: str = "smtp.gmail.com",
        smtp_port: int = 587,
        sender_email: Optional[str] = None,
        sender_password: Optional[str] = None,
    ) -> None:
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.is_configured = bool(sender_email and sender_password)

    def send_alert(
        self,
        recipient_email: str,
        alert_type: str,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        confidence: float,
        threat_details: str = "",
    ) -> bool:
        """
        Send a security alert email.

        Args:
            recipient_email: Email address to send to
            alert_type: Type of attack (e.g., "Brute Force")
            source_ip: Source IP address
            dest_ip: Destination IP address
            dest_port: Destination port
            confidence: Confidence score (0.0-1.0)
            threat_details: Additional threat context

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_configured:
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 ZeroBit Security Alert: {alert_type}"
            msg["From"] = self.sender_email
            msg["To"] = recipient_email

            # Create HTML version of email
            html = self._create_html_body(
                alert_type, source_ip, dest_ip, dest_port, confidence, threat_details
            )

            part = MIMEText(html, "html")
            msg.attach(part)

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, recipient_email, msg.as_string())

            return True
        except Exception as e:
            print(f"Error sending email alert: {str(e)}")
            return False

    def send_batch_alerts(
        self,
        recipient_emails: List[str],
        alerts: List[dict],
    ) -> int:
        """
        Send multiple alerts to multiple recipients.

        Args:
            recipient_emails: List of recipient emails
            alerts: List of alert dictionaries

        Returns:
            Number of emails sent successfully
        """
        sent_count = 0
        for email in recipient_emails:
            for alert in alerts:
                if self.send_alert(
                    email,
                    alert.get("alert_type", "Unknown"),
                    alert.get("source_ip", ""),
                    alert.get("dest_ip", ""),
                    alert.get("dest_port", 0),
                    alert.get("confidence", 0.0),
                    alert.get("threat_details", ""),
                ):
                    sent_count += 1
        return sent_count

    @staticmethod
    def _create_html_body(
        alert_type: str,
        source_ip: str,
        dest_ip: str,
        dest_port: int,
        confidence: float,
        threat_details: str,
    ) -> str:
        """Create HTML email body with formatting."""
        confidence_pct = round(confidence * 100, 1)
        severity = "CRITICAL" if confidence > 0.85 else "HIGH" if confidence > 0.7 else "MEDIUM"

        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
                <div style="background-color: white; border-left: 5px solid #d32f2f; padding: 20px; border-radius: 5px;">
                    <h2 style="color: #d32f2f; margin-top: 0;">🚨 Security Alert: {alert_type}</h2>
                    
                    <div style="background-color: #fce4ec; padding: 10px; border-radius: 3px; margin: 10px 0;">
                        <p style="margin: 5px 0;"><strong>Severity:</strong> <span style="color: #d32f2f; font-weight: bold;">{severity}</span></p>
                        <p style="margin: 5px 0;"><strong>Confidence:</strong> {confidence_pct}%</p>
                        <p style="margin: 5px 0;"><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    
                    <h3 style="color: #333; margin-top: 20px;">Attack Details</h3>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold;">Source IP:</td>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-family: monospace;">{source_ip}</td>
                        </tr>
                        <tr style="background-color: #fafafa;">
                            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold;">Target IP:</td>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-family: monospace;">{dest_ip}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold;">Target Port:</td>
                            <td style="padding: 8px; border-bottom: 1px solid #ddd; font-family: monospace;">{dest_port}</td>
                        </tr>
                    </table>
                    
                    {f'''<h3 style="color: #333; margin-top: 20px;">Threat Context</h3>
                    <p style="background-color: #f9f9f9; padding: 10px; border-radius: 3px;">{threat_details}</p>''' if threat_details else ''}
                    
                    <h3 style="color: #333; margin-top: 20px;">Recommended Actions</h3>
                    <ul style="line-height: 1.8;">
                        <li>Investigate the source IP immediately</li>
                        <li>Check firewall and IDS logs for related activity</li>
                        <li>Review target system logs for successful compromise</li>
                        <li>Block source IP if threat is confirmed</li>
                        <li>Update threat intelligence with new IOCs</li>
                    </ul>
                    
                    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                    <p style="color: #999; font-size: 12px; margin: 0;">
                        This is an automated alert from ZeroBit Network Intrusion Detection System.
                        Do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        """
        return html
