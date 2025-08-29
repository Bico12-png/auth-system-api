from flask_sqlalchemy import SQLAlchemy
from src.models.user import db
from datetime import datetime
import random
import string

class Key(db.Model):
    __tablename__ = 'keys'
    
    key_id = db.Column(db.String(8), primary_key=True)
    expiration_days = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    first_login_at = db.Column(db.DateTime, nullable=True)
    hwid = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Key {self.key_id}>'
    
    def to_dict(self):
        return {
            'key_id': self.key_id,
            'expiration_days': self.expiration_days,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'first_login_at': self.first_login_at.isoformat() if self.first_login_at else None,
            'hwid': self.hwid,
            'is_active': self.is_active,
            'is_expired': self.is_expired(),
            'is_used': self.hwid is not None
        }
    
    def is_expired(self):
        if not self.first_login_at:
            return False
        from datetime import timedelta
        expiry_date = self.first_login_at + timedelta(days=self.expiration_days)
        return datetime.utcnow() > expiry_date
    
    @staticmethod
    def generate_unique_key():
        """Gera uma chave única de 8 dígitos"""
        while True:
            key = ''.join(random.choices(string.digits, k=8))
            if not Key.query.filter_by(key_id=key).first():
                return key

class AccessLog(db.Model):
    __tablename__ = 'access_logs'
    
    log_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    key_id = db.Column(db.String(8), db.ForeignKey('keys.key_id'), nullable=False)
    login_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    hwid_attempt = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # 'success' ou 'failure'
    message = db.Column(db.String(255), nullable=True)
    
    def __repr__(self):
        return f'<AccessLog {self.log_id}>'
    
    def to_dict(self):
        return {
            'log_id': self.log_id,
            'key_id': self.key_id,
            'login_at': self.login_at.isoformat() if self.login_at else None,
            'ip_address': self.ip_address,
            'hwid_attempt': self.hwid_attempt,
            'status': self.status,
            'message': self.message
        }

