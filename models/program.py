import datetime

from extensions import db


class Program(db.Model):
    __tablename__ = 'programs'
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name       = db.Column(db.String(200), nullable=False)
    platform   = db.Column(db.String(100))
    scope      = db.Column(db.Text)
    policy_url = db.Column(db.String(500))
    status     = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    vulnerabilities = db.relationship('Vulnerability', backref='program', lazy=True)
