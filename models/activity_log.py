import datetime

from extensions import db


class ActivityLog(db.Model):
    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey('user.id'))
    action           = db.Column(db.String(100))
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerability.id'))
    timestamp        = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    details          = db.Column(db.Text)
