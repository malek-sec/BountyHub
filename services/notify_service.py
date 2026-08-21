import re

import requests
from flask import current_app


# Severity → Discord embed integer color
_SEV_COLORS = {
    'critical': 0xef4444,
    'high':     0xf97316,
    'medium':   0xf59e0b,
    'low':      0x3b82f6,
}
_DEFAULT_COLOR = 0x06b6d4   # cyan (app theme)


def _to_markdown(html: str, bold: str = "*") -> str:
    """Convert Telegram HTML (<b>…</b>) to Slack/Discord markdown."""
    text = re.sub(
        r'<b>(.*?)</b>',
        lambda m: f"{bold}{m.group(1)}{bold}",
        html,
        flags=re.DOTALL,
    )
    return re.sub(r'<[^>]+>', '', text)


def _severity_color(message: str) -> int:
    """Extract severity word from message and map to a Discord color int."""
    m = re.search(r'severity[:\s]*(?:<[^>]+>)*\s*(\w+)', message, re.IGNORECASE)
    if m:
        return _SEV_COLORS.get(m.group(1).lower(), _DEFAULT_COLOR)
    return _DEFAULT_COLOR


class NotifyService:

    @staticmethod
    def send(message: str) -> None:
        """
        POST a plain-text message to the configured Telegram chat.

        * No-op when TELEGRAM_TOKEN or TELEGRAM_CHAT_ID are not set.
        * 5-second network timeout — never blocks a request or worker thread.
        * Catches ALL exceptions so a Telegram outage can never crash the caller.
        """
        token   = current_app.config.get("TELEGRAM_TOKEN", "").strip()
        chat_id = current_app.config.get("TELEGRAM_CHAT_ID", "").strip()
        if not token or not chat_id:
            return
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "HTML"}
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
        except Exception:
            pass

    @staticmethod
    def send_slack(message: str) -> None:
        """
        POST to SLACK_WEBHOOK_URL using Slack Block Kit (section + mrkdwn).
        No-op when SLACK_WEBHOOK_URL is empty.
        """
        url = current_app.config.get("SLACK_WEBHOOK_URL", "").strip()
        if not url:
            return
        text    = _to_markdown(message, bold="*")
        payload = {
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text},
                }
            ]
        }
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
        except Exception:
            pass

    @staticmethod
    def send_discord(message: str) -> None:
        """
        POST to DISCORD_WEBHOOK_URL using a Discord embed.
        Color is derived from the severity word in the message.
        No-op when DISCORD_WEBHOOK_URL is empty.
        """
        url = current_app.config.get("DISCORD_WEBHOOK_URL", "").strip()
        if not url:
            return
        text    = _to_markdown(message, bold="**")
        payload = {
            "embeds": [
                {
                    "description": text,
                    "color":       _severity_color(message),
                }
            ]
        }
        try:
            resp = requests.post(url, json=payload, timeout=5)
            resp.raise_for_status()
        except Exception:
            pass

    @staticmethod
    def notify_all(message: str) -> None:
        """
        Broadcast to every configured channel: Telegram, Slack, Discord.
        Each channel is wrapped in its own try/except so one failure
        never prevents the others from firing.
        """
        for fn in (
            NotifyService.send,
            NotifyService.send_slack,
            NotifyService.send_discord,
        ):
            try:
                fn(message)
            except Exception:
                pass
