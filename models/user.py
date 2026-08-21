import datetime

from flask_login import UserMixin

from extensions import db


class User(UserMixin, db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    username   = db.Column(db.String(100), unique=True)
    password   = db.Column(db.String(100))
    email      = db.Column(db.String(150))
    role       = db.Column(db.String(50), default='researcher')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
