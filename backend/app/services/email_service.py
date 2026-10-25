"""Transactional verification-email delivery."""

from __future__ import annotations

import html
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlencode
from uuid import UUID

import aiosmtplib
from ..core.config import settings


class EmailService:
    def __init__(self, _db, _tenant_id: UUID) -> None:
        # Email delivery is intentionally kept outside the database transaction.
        pass

    async def send_existing_verification_token(self, user_id: UUID, email: str, token: str) -> None:
        query = urlencode({"token": token, "user_id": str(user_id)})
        link = f"{settings.FRONTEND_URL}/verify-email?{query}"
        subject = "Verify your email address"
        body = (
            "<p>Use the link below to verify your email address.</p>"
            f'<p><a href="{html.escape(link, quote=True)}">Verify email</a></p>'
            f"<p>This link expires in {settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS} hours.</p>"
        )
        message = MIMEMultipart("alternative")
        message["From"] = settings.SMTP_FROM_EMAIL
        message["To"] = email
        message["Subject"] = subject
        message.attach(MIMEText(body, "html", "utf-8"))
        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USER,
            password=settings.SMTP_PASSWORD,
            start_tls=settings.SMTP_USE_TLS,
            timeout=settings.SMTP_TIMEOUT_SECONDS,
        )
