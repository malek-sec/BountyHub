import datetime
import hashlib
from functools import wraps

from flask import flash, redirect, url_for
from flask_login import current_user

from extensions import db


class FeatureFlag(db.Model):
    __tablename__ = 'feature_flags'
    id                 = db.Column(db.Integer, primary_key=True)
    name               = db.Column(db.String(100), unique=True, nullable=False)
    description        = db.Column(db.String(255))
    enabled            = db.Column(db.Boolean, default=False)
    rollout_percentage = db.Column(db.Integer, default=0)
    created_at         = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at         = db.Column(db.DateTime, default=datetime.datetime.utcnow,
                                   onupdate=datetime.datetime.utcnow)


class FeatureFlagService:
    @staticmethod
    def is_enabled(flag_name: str, user_id: int | None = None) -> bool:
        flag = FeatureFlag.query.filter_by(name=flag_name).first()
        if not flag or not flag.enabled:
            return False
        if flag.rollout_percentage > 0 and user_id:
            hash_input = f"{flag_name}:{user_id}".encode()
            user_hash  = int(hashlib.md5(hash_input, usedforsecurity=False).hexdigest(), 16)
            if (user_hash % 100) < flag.rollout_percentage:
                return True
        return flag.rollout_percentage == 100


def require_feature(flag_name: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = current_user.id if current_user.is_authenticated else None
            if not FeatureFlagService.is_enabled(flag_name, user_id):
                flash('هذه الميزة غير متاحة حالياً', 'warning')
                return redirect(url_for('vulnerabilities.home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator
