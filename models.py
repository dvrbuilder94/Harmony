# Simple JWT Auth models
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

from app import db


class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_password(self, password):
        """Set password hash."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash."""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user to dict for JSON response."""
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class Venta(db.Model):
    __tablename__ = 'ventas'
    
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    fecha = db.Column(db.Date, nullable=False)
    canal = db.Column(db.String(50), nullable=False)
    monto_bruto = db.Column(db.Numeric(12, 2), nullable=False)
    comision = db.Column(db.Numeric(12, 2), nullable=False)
    impuestos = db.Column(db.Numeric(12, 2), nullable=False)
    devoluciones = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    monto_neto = db.Column(db.Numeric(12, 2), nullable=False)
    
    # Optional fields for detailed tracking
    order_id = db.Column(db.String(255), nullable=True)
    product_name = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('ventas', lazy=True))
    
    def to_dict(self):
        """Convert venta to dict for JSON response."""
        return {
            'id': self.id,
            'fecha': self.fecha.isoformat(),
            'canal': self.canal,
            'monto_bruto': float(self.monto_bruto),
            'comision': float(self.comision),
            'impuestos': float(self.impuestos),
            'devoluciones': float(self.devoluciones),
            'monto_neto': float(self.monto_neto),
            'order_id': self.order_id,
            'product_name': self.product_name,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class Pago(db.Model):
    __tablename__ = 'pagos'
    
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    fecha = db.Column(db.Date, nullable=False)
    monto = db.Column(db.Numeric(12, 2), nullable=False)
    referencia = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('pagos', lazy=True))
    
    def to_dict(self):
        """Convert pago to dict for JSON response."""
        return {
            'id': self.id,
            'fecha': self.fecha.isoformat(),
            'monto': float(self.monto),
            'referencia': self.referencia,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class MercadoLibreAccount(db.Model):
    __tablename__ = 'mercado_libre_accounts'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False, unique=True)
    meli_user_id = db.Column(db.String(64), nullable=True)
    access_token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text, nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('mercado_libre_account', uselist=False))

    def is_token_expired(self) -> bool:
        if not self.token_expires_at:
            return False
        return datetime.utcnow() >= self.token_expires_at

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'meli_user_id': self.meli_user_id,
            'has_refresh_token': bool(self.refresh_token),
            'token_expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }