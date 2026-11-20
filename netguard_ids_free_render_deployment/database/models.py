from extensions import db
from datetime import datetime

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100))
    attack_type = db.Column(db.String(100))
    protocol = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class NetworkLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(100))
    destination_ip = db.Column(db.String(100))
    protocol = db.Column(db.String(20))
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
