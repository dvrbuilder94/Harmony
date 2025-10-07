# Simple JWT Auth models
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

from app import db
from typing import Optional


class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(100), nullable=True)
    role = db.Column(db.String(50), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=True)
    # Email verification fields
    is_email_verified = db.Column(db.Boolean, default=False)
    email_verified_at = db.Column(db.DateTime, nullable=True)
    email_verification_sent_at = db.Column(db.DateTime, nullable=True)
    
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
            'is_email_verified': self.is_email_verified,
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

    @staticmethod
    def _get_fernet():
        key = os.environ.get('ENCRYPTION_KEY')
        if not key:
            raise RuntimeError('ENCRYPTION_KEY is required for token encryption')
        if isinstance(key, str):
            key = key.encode()
        return Fernet(key)

    def set_tokens(self, access_token: str, refresh_token: Optional[str], expires_at):
        f = self._get_fernet()
        self.access_token = f.encrypt(access_token.encode()).decode()
        self.refresh_token = f.encrypt(refresh_token.encode()).decode() if refresh_token else None
        self.token_expires_at = expires_at

    def get_access_token(self) -> str:
        f = self._get_fernet()
        return f.decrypt(self.access_token.encode()).decode()

    def get_refresh_token(self) -> Optional[str]:
        if not self.refresh_token:
            return None
        f = self._get_fernet()
        return f.decrypt(self.refresh_token.encode()).decode()


class MLOrder(db.Model):
    __tablename__ = 'ml_orders'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    order_id = db.Column(db.String(64), nullable=False)
    date_created = db.Column(db.String(64), nullable=True)
    currency_id = db.Column(db.String(8), nullable=True)
    total_amount = db.Column(db.Float, nullable=False, default=0)
    status = db.Column(db.String(32), nullable=True)
    buyer_nickname = db.Column(db.String(128), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'order_id', name='uq_ml_order_user_order'),
    )

    items = db.relationship('MLOrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

    def to_dict(self, include_items: bool = True):
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'order_id': self.order_id,
            'date_created': self.date_created,
            'currency_id': self.currency_id,
            'total_amount': self.total_amount,
            'status': self.status,
            'buyer_nickname': self.buyer_nickname,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }
        if include_items:
            data['items'] = [i.to_dict() for i in self.items]
        return data


class MLOrderItem(db.Model):
    __tablename__ = 'ml_order_items'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    ml_order_id = db.Column(db.String, db.ForeignKey('ml_orders.id'), nullable=False)
    title = db.Column(db.String(512), nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    unit_price = db.Column(db.Float, nullable=False, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'ml_order_id': self.ml_order_id,
            'title': self.title,
            'quantity': self.quantity,
            'unit_price': self.unit_price,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class MercadoLibreCredentials(db.Model):
    __tablename__ = 'mercado_libre_credentials'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False, unique=True)
    client_id = db.Column(db.String(128), nullable=False)
    client_secret_encrypted = db.Column(db.Text, nullable=False)
    site_id = db.Column(db.String(8), nullable=True)
    redirect_uri = db.Column(db.String(500), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('mercado_libre_credentials', uselist=False))

    @staticmethod
    def _fernet() -> Fernet:
        key = os.environ.get('ENCRYPTION_KEY')
        if not key:
            raise RuntimeError('ENCRYPTION_KEY is required for credentials encryption')
        if isinstance(key, str):
            key = key.encode()
        return Fernet(key)

    def set_client_secret(self, client_secret: str):
        f = self._fernet()
        self.client_secret_encrypted = f.encrypt(client_secret.encode()).decode()

    def get_client_secret(self) -> str:
        f = self._fernet()
        return f.decrypt(self.client_secret_encrypted.encode()).decode()

    def to_safe_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'client_id': self.client_id,
            'site_id': self.site_id,
            'redirect_uri': self.redirect_uri,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


# Canonical normalized models for dashboards across marketplaces
class CanonOrder(db.Model):
    __tablename__ = 'orders_canonical'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    channel = db.Column(db.String(32), nullable=False)  # e.g., 'meli', 'falabella'
    external_id = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(32), nullable=True)
    currency_id = db.Column(db.String(8), nullable=True)
    gross_amount = db.Column(db.Float, nullable=False, default=0)
    net_amount = db.Column(db.Float, nullable=True)
    buyer_name = db.Column(db.String(256), nullable=True)

    created_row_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_row_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'channel', 'external_id', name='uq_canon_user_channel_external'),
    )

    items = db.relationship('CanonOrderItem', backref='order', lazy=True, cascade="all, delete-orphan")

    def to_ui_dict(self, include_items: bool = False):
        data = {
            'id': self.id,
            'order_id': self.external_id,
            'date_created': self.created_at,
            'status': self.status,
            'currency_id': self.currency_id,
            'total_amount': self.gross_amount,
            'buyer_nickname': self.buyer_name,
        }
        if include_items:
            data['items'] = [i.to_dict() for i in self.items]
        return data


class CanonOrderItem(db.Model):
    __tablename__ = 'order_items_canonical'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    order_id = db.Column(db.String, db.ForeignKey('orders_canonical.id'), nullable=False)
    sku = db.Column(db.String(128), nullable=True)
    title = db.Column(db.String(512), nullable=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    unit_price = db.Column(db.Float, nullable=False, default=0)

    created_row_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_row_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'sku': self.sku,
            'title': self.title,
            'quantity': self.quantity,
            'unit_price': self.unit_price,
        }


class FalabellaCredentials(db.Model):
    __tablename__ = 'falabella_credentials'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False, unique=True)
    client_id = db.Column(db.String(128), nullable=False)
    client_secret_encrypted = db.Column(db.Text, nullable=False)
    api_base_url = db.Column(db.String(500), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('falabella_credentials', uselist=False))

    @staticmethod
    def _fernet() -> Fernet:
        key = os.environ.get('ENCRYPTION_KEY')
        if not key:
            raise RuntimeError('ENCRYPTION_KEY is required for credentials encryption')
        if isinstance(key, str):
            key = key.encode()
        return Fernet(key)

    def set_client_secret(self, client_secret: str):
        f = self._fernet()
        self.client_secret_encrypted = f.encrypt(client_secret.encode()).decode()

    def get_client_secret(self) -> str:
        f = self._fernet()
        return f.decrypt(self.client_secret_encrypted.encode()).decode()

    def to_safe_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'client_id': self.client_id,
            'api_base_url': self.api_base_url,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


# Financial canonical models
class CanonPayment(db.Model):
    __tablename__ = 'payments_canonical'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    order_id = db.Column(db.String, db.ForeignKey('orders_canonical.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0)
    method = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(32), nullable=True)
    paid_at = db.Column(db.String(64), nullable=True)
    external_id = db.Column(db.String(128), nullable=True)

    created_row_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_row_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CanonFee(db.Model):
    __tablename__ = 'fees_canonical'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    order_id = db.Column(db.String, db.ForeignKey('orders_canonical.id'), nullable=False)
    kind = db.Column(db.String(64), nullable=True)
    amount = db.Column(db.Float, nullable=False, default=0)

    created_row_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_row_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CanonPayout(db.Model):
    __tablename__ = 'payouts_canonical'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    order_id = db.Column(db.String, db.ForeignKey('orders_canonical.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False, default=0)
    paid_out_at = db.Column(db.String(64), nullable=True)
    external_id = db.Column(db.String(128), nullable=True)

    created_row_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_row_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BankTransaction(db.Model):
    __tablename__ = 'bank_transactions'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String, db.ForeignKey('users.id'), nullable=False)
    account_id = db.Column(db.String(64), nullable=True)
    date = db.Column(db.String(64), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(512), nullable=True)
    external_id = db.Column(db.String(128), nullable=True)

    created_row_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_row_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Conciliation(db.Model):
    __tablename__ = 'conciliations'

    id = db.Column(db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    payout_id = db.Column(db.String, db.ForeignKey('payouts_canonical.id'), nullable=False)
    bank_transaction_id = db.Column(db.String, db.ForeignKey('bank_transactions.id'), nullable=False)
    status = db.Column(db.String(32), nullable=False, default='conciliated')  # conciliated|manual|pending
    match_type = db.Column(db.String(32), nullable=True)  # exact|tolerated|manual
    diff_amount = db.Column(db.Float, nullable=True)

    created_row_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_row_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)