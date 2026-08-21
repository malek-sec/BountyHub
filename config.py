import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / '.env')

_basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # ── Security ──────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "").strip()

    # ── Database ──────────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI    = 'sqlite:///' + os.path.join(_basedir, 'bounty_hub.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── File storage ──────────────────────────────────────────────────────────
    UPLOAD_FOLDER      = os.path.join(_basedir, 'static', 'uploads')
    SCREENSHOTS_FOLDER = os.path.join(_basedir, 'static', 'screenshots')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024   # 5 MB hard cap for all uploads

    # ── External services ─────────────────────────────────────────────────────
    TELEGRAM_TOKEN      = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    TELEGRAM_CHAT_ID    = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    SLACK_WEBHOOK_URL   = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    ANTHROPIC_API_KEY   = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    # ── Scan engine ───────────────────────────────────────────────────────────
    V2_ROOT = os.path.abspath(os.path.join(_basedir, '..', 'scan-engine'))

    # ── Validation ────────────────────────────────────────────────────────────
    @classmethod
    def validate(cls) -> None:
        if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 32:
            raise RuntimeError(
                "FLASK_SECRET_KEY env var is missing or too short (min 32 chars). "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )
