"""One-time image captcha service backed by Redis."""

from __future__ import annotations

import hmac
import secrets
import string
from io import BytesIO
from pathlib import Path

import redis.asyncio as redis
from PIL import Image, ImageDraw, ImageFont

from ..core.config import settings


class CaptchaService:
    def __init__(self, redis_client: redis.Redis) -> None:
        self.redis = redis_client

    async def generate(self) -> tuple[str, bytes]:
        code = "".join(
            secrets.choice(string.ascii_uppercase + string.digits)
            for _ in range(settings.CAPTCHA_LENGTH)
        )
        token = secrets.token_urlsafe(32)
        await self.redis.setex(f"captcha:{token}", settings.CAPTCHA_EXPIRE_SECONDS, code)
        return token, self._create_image(code)

    async def verify(self, token: str, user_input: str) -> bool:
        if not token or not user_input:
            return False
        # Atomic GET+DEL without requiring Redis 6.2 GETDEL support.
        script = "local v = redis.call('GET', KEYS[1]); if v then redis.call('DEL', KEYS[1]); end; return v"
        code = await self.redis.eval(script, 1, f"captcha:{token}")
        if not code:
            return False
        if isinstance(code, bytes):
            code = code.decode("utf-8")
        return hmac.compare_digest(str(code).upper(), user_input.strip().upper())

    @staticmethod
    def _create_image(text: str) -> bytes:
        width, height = 160, 52
        image = Image.new("RGB", (width, height), "white")
        draw = ImageDraw.Draw(image)
        for _ in range(7):
            draw.line(
                (secrets.randbelow(width), secrets.randbelow(height), secrets.randbelow(width), secrets.randbelow(height)),
                fill=(150, 150, 150),
                width=1,
            )
        font = ImageFont.load_default()
        font_paths = (
            settings.CAPTCHA_FONT_PATH,
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "C:/Windows/Fonts/arialbd.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
        )
        for font_path in font_paths:
            if font_path and Path(font_path).is_file():
                font = ImageFont.truetype(font_path, 30)
                break
        bbox = draw.textbbox((0, 0), text, font=font)
        draw.text(((width - (bbox[2] - bbox[0])) / 2, (height - (bbox[3] - bbox[1])) / 2), text, fill="black", font=font)
        output = BytesIO()
        image.save(output, "PNG")
        return output.getvalue()
