import datetime

from extensions import db


class ScanJob(db.Model):
    __tablename__   = 'scan_jobs'
    id              = db.Column(db.Integer, primary_key=True)
    scan_id         = db.Column(db.String(36), unique=True, nullable=False)
    user_id         = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target          = db.Column(db.String(253), nullable=False)
    status          = db.Column(db.String(20), default='queued')
    stage           = db.Column(db.String(50),  nullable=True)
    stage_label     = db.Column(db.String(150), nullable=True)
    hosts_found     = db.Column(db.Integer, default=0)
    hosts_scanned   = db.Column(db.Integer, default=0)
    result          = db.Column(db.Text, nullable=True)
    analyses        = db.Column(db.Text, nullable=True)
    diff            = db.Column(db.Text, nullable=True)
    error           = db.Column(db.Text, nullable=True)
    log             = db.Column(db.Text, default='[]')
    created_at      = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    completed_at    = db.Column(db.DateTime, nullable=True)
