import datetime
import json

from extensions import db

CACHE_TTL_DAYS = 7


class CVECache(db.Model):
    __tablename__ = 'cve_cache'

    technology_key = db.Column(db.String(200), primary_key=True)
    results_json   = db.Column(db.Text, nullable=False)
    cached_at      = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at     = db.Column(db.DateTime, nullable=False)
    hit_count      = db.Column(db.Integer, default=0)

    @classmethod
    def get(cls, key: str) -> list[dict] | None:
        key = key.strip().lower()
        entry = cls.query.get(key)
        if entry is None:
            return None
        if entry.expires_at < datetime.datetime.utcnow():
            return None
        try:
            entry.hit_count = (entry.hit_count or 0) + 1
            db.session.commit()
        except Exception:
            db.session.rollback()
        try:
            return json.loads(entry.results_json)
        except Exception:
            return None

    @classmethod
    def set(cls, key: str, results: list[dict]) -> None:
        key = key.strip().lower()
        try:
            now        = datetime.datetime.utcnow()
            expires_at = now + datetime.timedelta(days=CACHE_TTL_DAYS)
            entry = cls.query.get(key)
            if entry is None:
                entry = cls(
                    technology_key=key,
                    results_json=json.dumps(results),
                    cached_at=now,
                    expires_at=expires_at,
                    hit_count=0,
                )
                db.session.add(entry)
            else:
                entry.results_json = json.dumps(results)
                entry.cached_at    = now
                entry.expires_at   = expires_at
                entry.hit_count    = 0
            db.session.commit()
        except Exception:
            db.session.rollback()
