import os
import logging
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from sqlalchemy import text, select
from flask_migrate import Migrate
import requests
from urllib.parse import urlencode
from cryptography.fernet import Fernet

# Configure logging first
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Implement simple JWT using PyJWT
import jwt
import os
from functools import wraps
from datetime import datetime, timedelta

JWT_AVAILABLE = True

# Critical security: JWT secret must be set in environment
load_dotenv()
JWT_SECRET_KEY = os.environ.get("SESSION_SECRET")
if not JWT_SECRET_KEY:
    logger.error("CRITICAL: SESSION_SECRET environment variable is required for JWT security")
    raise RuntimeError("SESSION_SECRET environment variable must be set for JWT authentication")

JWT_ALGORITHM = "HS256"

def create_access_token(identity):
    """Create JWT token with user identity."""
    payload = {
        'user_id': identity,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def create_state_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=10),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def decode_state_token(state_token):
    return jwt.decode(state_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

def jwt_required(f):
    """Decorator for protecting endpoints with JWT."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from Authorization header - strict Bearer format
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if not auth_header.startswith('Bearer '):
                return api_error("Invalid authorization header format. Use 'Bearer <token>'", 401)
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return api_error("Invalid authorization header format. Use 'Bearer <token>'", 401)
        
        if not token:
            return api_error("Authorization header with Bearer token is required", 401)
        
        try:
            # Debug logging
            logger.debug("Attempting to decode JWT token")
            
            # Decode and verify token
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            current_user_id = payload['user_id']
            
            logger.debug(f"JWT decoded successfully, user_id: {current_user_id}")
            
            # Set current user ID for the request (using Flask's g object instead of request)
            from flask import g
            g.current_user_id = current_user_id
            
        except jwt.ExpiredSignatureError as e:
            logger.error(f"JWT expired: {e}")
            return api_error("Token has expired", 401)
        except jwt.InvalidTokenError as e:
            logger.error(f"JWT invalid: {e}")
            return api_error("Token is invalid", 401)
        except Exception as e:
            logger.error(f"JWT decode error: {e}")
            return api_error("Token validation failed", 401)
        
        return f(*args, **kwargs)
    
    return decorated_function

def get_jwt_identity():
    """Get current user ID from JWT token."""
    from flask import g
    return getattr(g, 'current_user_id', None)


# SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Create Flask app
app = Flask(__name__, static_folder='static', static_url_path='/static')

# Configuration helper function
def get_database_url():
    """Get appropriate database URL with fallback to SQLite."""
    database_url = os.environ.get("DATABASE_URL")
    
    if database_url:
        # Check if it's the disabled Neon endpoint
        if "neon.tech" in database_url and "ep-green-frog" in database_url:
            logger.warning("Detected disabled Neon endpoint, falling back to SQLite")
            return "sqlite:///salesharmony.db"
        # For working PostgreSQL URLs
        return database_url
    
    # Default fallback
    return "sqlite:///salesharmony.db"

# Configuration - enforce secure secret
app.secret_key = os.environ.get("SESSION_SECRET")  # Follow dev guidelines exactly
app.config["SQLALCHEMY_DATABASE_URI"] = get_database_url()
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure engine options based on database type
db_url = app.config["SQLALCHEMY_DATABASE_URI"]
if db_url.startswith("sqlite"):
    # SQLite configuration
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
    }
    logger.info("Using SQLite database for development")
else:
    # PostgreSQL configuration
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }
    logger.info("Using PostgreSQL database")

# JWT Configuration (simple implementation)
if JWT_AVAILABLE:
    app.config["JWT_SECRET_KEY"] = app.config["SECRET_KEY"]
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

# Initialize SQLAlchemy
db = SQLAlchemy(app, model_class=Base)
Migrate(app, db)

# Configure CORS (env-driven) and ensure preflight matches
allowed_origins_env = os.environ.get("ALLOWED_ORIGINS")
if allowed_origins_env:
    origins_list = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
else:
    origins_list = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

# If wildcard requested, pass "*" (not ["*"])
origins_param = "*" if len(origins_list) == 1 and origins_list[0] == "*" else origins_list

CORS(
    app,
    resources={r"/*": {"origins": origins_param}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    supports_credentials=False,
    send_wildcard=True if origins_param == "*" else False,
)

# ProxyFix for proper URL generation
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Import models after app setup
with app.app_context():
    try:
        import models  # This will import our clean models
        db.create_all()  # Create tables
        logger.info("Database initialized successfully")
        
        # Create test users ONLY in development mode for security
        if os.environ.get('FLASK_ENV') == 'development' or os.environ.get('SEED_TEST_USERS') == 'true':
            from models import User
            
            test_users = [
                {
                    'email': 'admin@salesharmony.com',
                    'password': 'admin123',
                    'name': 'Admin Usuario',
                    'role': 'admin'
                },
                {
                    'email': 'vendedor@salesharmony.com', 
                    'password': 'vendedor123',
                    'name': 'Vendedor Usuario',
                    'role': 'user'
                },
                {
                    'email': 'demo@salesharmony.com', 
                    'password': 'demo123',
                    'name': 'Usuario Demo',
                    'role': 'user'
                }
            ]
            
            for user_data in test_users:
                existing_user = User.query.filter_by(email=user_data['email']).first()
                if not existing_user:
                    new_user = User(
                        email=user_data['email'],
                        name=user_data['name'],
                        role=user_data['role'],
                        is_active=True
                    )
                    new_user.set_password(user_data['password'])  # Use hashed password
                    db.session.add(new_user)
                    logger.info(f"Created test user: {user_data['email']}")
            
            db.session.commit()
            logger.info("Test users initialized successfully (development mode only)")
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        # Continue anyway, we can debug this later

# Helper functions
def api_response(data=None, message=None, status_code=200):
    """Create standardized API response."""
    response_data = {
        "success": 200 <= status_code < 300,
        "status_code": status_code,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if message:
        response_data["message"] = message
    
    if data is not None:
        response_data["data"] = data
    
    return jsonify(response_data), status_code

def api_error(message, status_code=400, details=None):
    """Create standardized API error response."""
    error_data = {
        "success": False,
        "status_code": status_code,
        "timestamp": datetime.utcnow().isoformat(),
        "message": message
    }
    
    if details:
        error_data["details"] = details
    
    return jsonify(error_data), status_code

# Health check endpoint
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    try:
        # Test database connection
        db.session.execute(text("SELECT 1"))
        
        return api_response({
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.utcnow().isoformat(),
            "jwt_available": JWT_AVAILABLE
        }, "Service is healthy")
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return api_error("Service unhealthy", 503)

# Authentication endpoints
@app.route('/auth/register', methods=['POST'])
def register():
    """Register new user."""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return api_error("Email and password are required", 400)
        
        # Import User model here to avoid circular imports
        from models import User
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return api_error("Email already registered", 409)
        
        # Create new user
        user = User(
            email=data['email'],
            name=data.get('name', ''),
            role='user'  # Force all new registrations to be regular users
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        return api_response(
            user.to_dict(),
            "User registered successfully",
            201
        )
    
    except Exception as e:
        logger.error(f"Registration error: {e}")
        db.session.rollback()
        return api_error("Registration failed", 500)

@app.route('/auth/login', methods=['POST'])
def login():
    """Login user."""
    try:
        data = request.get_json()
        
        if not data or not data.get('email') or not data.get('password'):
            return api_error("Email and password are required", 400)
        
        from models import User
        
        # Find user
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not user.check_password(data['password']):
            return api_error("Invalid email or password", 401)
        
        if not user.is_active:
            return api_error("Account is deactivated", 401)
        
        # Create access token (if JWT is available)
        if JWT_AVAILABLE:
            access_token = create_access_token(identity=user.id)
            
            return api_response({
                "user": user.to_dict(),
                "access_token": access_token
            }, "Login successful")
        else:
            # Basic response without JWT for now
            return api_response({
                "user": user.to_dict(),
                "token": "basic-token-" + user.id  # Temporary for testing
            }, "Login successful (basic auth)")
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        return api_error("Login failed", 500)

# Mercado Libre OAuth endpoints
@app.route('/auth/meli/url', methods=['GET'])
@jwt_required
def meli_auth_url():
    try:
        current_user_id = get_jwt_identity()
        from models import MercadoLibreCredentials
        creds = MercadoLibreCredentials.query.filter_by(user_id=current_user_id).first()
        if not creds:
            return api_error("Mercado Libre credentials not configured for this user", 400)
        client_id = creds.client_id
        redirect_uri = creds.redirect_uri
        if not client_id or not redirect_uri:
            return api_error("Incomplete Mercado Libre credentials", 400)
        state = create_state_token(current_user_id)
        params = urlencode({
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'state': state
        })
        url = f"https://auth.mercadolibre.com/authorization?{params}"
        return api_response({"auth_url": url}, "Mercado Libre auth URL")
    except Exception as e:
        logger.error(f"MELI URL error: {e}")
        return api_error("Failed to create auth URL", 500)

@app.route('/auth/meli/callback', methods=['GET'])
def meli_callback():
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        if not code:
            return api_error("Missing code", 400)
        if not state:
            return api_error("Missing state", 400)

        from models import MercadoLibreCredentials
        client_id = None
        client_secret = None
        redirect_uri = None

        # Verify state and extract user id
        try:
            state_payload = decode_state_token(state)
            target_user_id = state_payload.get('user_id')
            if not target_user_id:
                return api_error("Invalid state payload", 400)
        except Exception as e:
            logger.error(f"Invalid state: {e}")
            return api_error("Invalid state", 400)

        # Load user-specific credentials
        creds = MercadoLibreCredentials.query.filter_by(user_id=target_user_id).first()
        if not creds:
            return api_error("Mercado Libre credentials not configured for this user", 400)
        client_id = creds.client_id
        client_secret = creds.get_client_secret()
        redirect_uri = creds.redirect_uri

        token_res = requests.post(
            "https://api.mercadolibre.com/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=20,
        )
        if token_res.status_code != 200:
            return api_error("Failed to exchange token", 502, details=token_res.text)
        token_json = token_res.json()

        # Identify correct user from state
        from models import User, MercadoLibreAccount
        user = User.query.get(target_user_id)
        if not user:
            return api_error("User from state not found", 404)

        expires_in = token_json.get('expires_in')
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None

        # Fetch Mercado Libre user info for reliable seller id
        access_token = token_json['access_token']
        me_res = requests.get(
            "https://api.mercadolibre.com/users/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=20,
        )
        meli_user_id = None
        if me_res.status_code == 200:
            try:
                me_json = me_res.json()
                meli_user_id = str(me_json.get('id')) if me_json.get('id') else None
            except Exception:
                meli_user_id = token_json.get('user_id')
        else:
            meli_user_id = token_json.get('user_id')

        existing = MercadoLibreAccount.query.filter_by(user_id=user.id).first()
        if not existing:
            existing = MercadoLibreAccount(
                user_id=user.id,
                meli_user_id=meli_user_id,
                access_token="",
                refresh_token=None,
                token_expires_at=expires_at,
            )
            db.session.add(existing)
        else:
            existing.token_expires_at = expires_at
            existing.meli_user_id = meli_user_id or existing.meli_user_id
        # Encrypt and set tokens
        existing.set_tokens(access_token, token_json.get('refresh_token'), expires_at)
        db.session.commit()

        # Redirect back to frontend if configured, to improve UX
        frontend_url = os.environ.get('FRONTEND_URL')
        if frontend_url:
            from flask import redirect
            # Redirect to channels page after successful OAuth
            return redirect(frontend_url.rstrip('/') + '/channels?meli=connected')

        return api_response(existing.to_dict(), "Mercado Libre connected")
    except Exception as e:
        logger.error(f"MELI callback error: {e}")
        db.session.rollback()
        return api_error("Failed to handle Mercado Libre callback", 500)

@app.route('/auth/me', methods=['GET'])
@jwt_required
def get_current_user():
    """Get current user info."""
    try:
        user_id = get_jwt_identity()
        from models import User
        
        user = User.query.get(user_id)
        if not user:
            return api_error("User not found", 404)
        
        return api_response(user.to_dict(), "User retrieved successfully")
    
    except Exception as e:
        logger.error(f"Get user error: {e}")
        return api_error("Failed to get user", 500)

# Sales endpoints - Protected with JWT
@app.route('/api/sales', methods=['GET'])
@jwt_required
def get_sales():
    """Get sales data for current user."""
    try:
        user_id = get_jwt_identity()
        from models import Venta
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        
        # Query sales filtered by current user using SQLAlchemy 2.0 style pagination
        sales = db.paginate(
            select(Venta).filter_by(user_id=user_id),
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return api_response({
            "sales": [sale.to_dict() for sale in sales.items],
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": sales.total,
                "pages": sales.pages
            }
        }, "Sales retrieved successfully")
        
    except Exception as e:
        logger.error(f"Get sales error: {e}")
        return api_error("Failed to get sales", 500)

@app.route('/api/sales', methods=['POST'])
@jwt_required
def create_sale():
    """Create new sale for current user."""
    try:
        user_id = get_jwt_identity()
        data = request.get_json()
        
        if not data:
            return api_error("Sale data is required", 400)
        
        from models import Venta
        from datetime import date
        
        # Create new sale with user_id automatically assigned
        sale = Venta(
            user_id=user_id,  # Automatically assign to current user
            fecha=date.today(),
            canal=data.get('canal', 'Web'),
            monto_bruto=data.get('monto_bruto', 0),
            comision=data.get('comision', 0),
            impuestos=data.get('impuestos', 0),
            devoluciones=data.get('devoluciones', 0),
            monto_neto=data.get('monto_neto', 0),
            order_id=data.get('order_id'),
            product_name=data.get('product_name')
        )
        
        db.session.add(sale)
        db.session.commit()
        
        return api_response(
            sale.to_dict(),
            "Sale created successfully",
            201
        )
        
    except Exception as e:
        logger.error(f"Create sale error: {e}")
        db.session.rollback()
        return api_error("Failed to create sale", 500)

# Mercado Libre sync endpoint (MVP - solo extracción)
@app.route('/api/meli/sync', methods=['POST'])
@jwt_required
def meli_sync_orders():
    try:
        current_user_id = get_jwt_identity()
        from models import MercadoLibreAccount, MLOrder, MLOrderItem, MercadoLibreCredentials, CanonOrder, CanonOrderItem

        account = MercadoLibreAccount.query.filter_by(user_id=current_user_id).first()
        if not account:
            return api_error("No Mercado Libre account linked", 400)

        # Refresh token if expired and we have refresh_token
        if getattr(account, 'token_expires_at', None) and account.token_expires_at <= datetime.utcnow():
            if account.refresh_token:
                creds = MercadoLibreCredentials.query.filter_by(user_id=current_user_id).first()
                if not creds:
                    return api_error("Mercado Libre credentials not configured for this user", 400)
                client_id = creds.client_id
                client_secret = creds.get_client_secret()
                if not client_id or not client_secret:
                    return api_error("MELI env vars missing for refresh", 500)
                refresh_res = requests.post(
                    "https://api.mercadolibre.com/oauth/token",
                    data={
                        "grant_type": "refresh_token",
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "refresh_token": account.get_refresh_token(),
                    },
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    timeout=20,
                )
                if refresh_res.status_code == 200:
                    t = refresh_res.json()
                    exp_in = t.get('expires_in')
                    new_expires = datetime.utcnow() + timedelta(seconds=exp_in) if exp_in else None
                    account.set_tokens(t['access_token'], t.get('refresh_token', account.get_refresh_token()), new_expires)
                    db.session.commit()
                else:
                    return api_error("Failed to refresh Mercado Libre token", 401, details=refresh_res.text)
            else:
                return api_error("Token expired and no refresh token available", 401)

        headers = {"Authorization": f"Bearer {account.get_access_token()}"}

        # Get recent orders (last 90 days) with simple pagination
        created_from = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        results = []
        limit = 50
        offset = 0
        max_pages = 20  # safety guard
        pages = 0
        while pages < max_pages:
            orders_url = (
                f"https://api.mercadolibre.com/orders/search/recent?seller={account.meli_user_id}"
                f"&order.date_created.from={created_from}&limit={limit}&offset={offset}"
            )
            res = requests.get(orders_url, headers=headers, timeout=30)
            if res.status_code != 200:
                return api_error("Failed to fetch orders from Mercado Libre", 502, details=res.text)
            data = res.json()
            batch = data.get('results', [])
            if not batch:
                break
            results.extend(batch)
            if len(batch) < limit:
                break
            offset += limit
            pages += 1

        saved = 0
        for order in results:
            oid = str(order.get('id'))
            existing = MLOrder.query.filter_by(user_id=current_user_id, order_id=oid).first()
            if existing:
                continue

            ml_order = MLOrder(
                user_id=current_user_id,
                order_id=oid,
                date_created=order.get('date_created'),
                currency_id=order.get('currency_id'),
                total_amount=float(order.get('total_amount') or 0),
                status=order.get('status'),
                buyer_nickname=(order.get('buyer') or {}).get('nickname')
            )
            db.session.add(ml_order)
            db.session.flush()

            for it in (order.get('order_items') or []):
                item = MLOrderItem(
                    ml_order_id=ml_order.id,
                    title=(it.get('item') or {}).get('title'),
                    quantity=it.get('quantity'),
                    unit_price=float(it.get('unit_price') or 0)
                )
                db.session.add(item)

            saved += 1

            # Map to canonical order + payout (MVP payout = gross_amount)
            canon_exists = CanonOrder.query.filter_by(user_id=current_user_id, channel='meli', external_id=oid).first()
            if not canon_exists:
                canon = CanonOrder(
                    user_id=current_user_id,
                    channel='meli',
                    external_id=oid,
                    created_at=order.get('date_created'),
                    status=order.get('status'),
                    currency_id=order.get('currency_id'),
                    gross_amount=float(order.get('total_amount') or 0),
                    net_amount=None,
                    buyer_name=(order.get('buyer') or {}).get('nickname'),
                )
                db.session.add(canon)
                db.session.flush()
                for it in (order.get('order_items') or []):
                    ci = CanonOrderItem(
                        order_id=canon.id,
                        sku=None,
                        title=(it.get('item') or {}).get('title'),
                        quantity=it.get('quantity') or 1,
                        unit_price=float(it.get('unit_price') or 0)
                    )
                    db.session.add(ci)
                # Create a payout record (mocked as gross for MVP)
                from models import CanonPayout
                po = CanonPayout(
                    order_id=canon.id,
                    amount=canon.gross_amount,
                    paid_out_at=None,
                    external_id=None,
                )
                db.session.add(po)

        db.session.commit()
        return api_response({"saved": saved, "fetched": len(results)}, "Mercado Libre sync persisted orders")
    except Exception as e:
        logger.error(f"MELI sync error: {e}")
        return api_error("Failed to sync Mercado Libre orders", 500)

# Unified orders endpoint (canonical)
@app.route('/api/orders', methods=['GET'])
@jwt_required
def list_orders():
    try:
        current_user_id = get_jwt_identity()
        from models import CanonOrder

        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        channel = request.args.get('channel')

        query = CanonOrder.query.filter_by(user_id=current_user_id)
        if channel:
            query = query.filter(CanonOrder.channel == channel)
        if status:
            query = query.filter(CanonOrder.status == status)
        if date_from:
            query = query.filter(CanonOrder.created_at >= date_from)
        if date_to:
            query = query.filter(CanonOrder.created_at <= date_to)

        orders = query.order_by(CanonOrder.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        data = [o.to_ui_dict(include_items=False) for o in orders.items]
        return api_response({
            "orders": data,
            "pagination": {"page": page, "per_page": per_page, "total": orders.total, "pages": orders.pages}
        })
    except Exception as e:
        logger.error(f"List orders error: {e}")
        return api_error("Failed to list orders", 500)

@app.route('/api/orders/export.csv', methods=['GET'])
@jwt_required
def export_orders_csv():
    try:
        import csv
        from io import StringIO
        current_user_id = get_jwt_identity()
        from models import CanonOrder
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        channel = request.args.get('channel')

        query = CanonOrder.query.filter_by(user_id=current_user_id)
        if channel:
            query = query.filter(CanonOrder.channel == channel)
        if status:
            query = query.filter(CanonOrder.status == status)
        if date_from:
            query = query.filter(CanonOrder.created_at >= date_from)
        if date_to:
            query = query.filter(CanonOrder.created_at <= date_to)
        rows = query.order_by(CanonOrder.created_at.desc()).all()

        buf = StringIO()
        writer = csv.writer(buf)
        writer.writerow(["order_id","channel","created_at","status","currency","gross_amount","buyer"])
        for o in rows:
            writer.writerow([o.external_id,o.channel,o.created_at,o.status,o.currency_id,o.gross_amount,o.buyer_name])
        buf.seek(0)
        return app.response_class(buf.getvalue(), mimetype='text/csv')
    except Exception as e:
        logger.error(f"Export CSV error: {e}")
        return api_error("Failed to export", 500)

@app.route('/admin/seed', methods=['POST'])
@jwt_required
def admin_seed():
    try:
        current_user_id = get_jwt_identity()
        from models import CanonOrder, CanonOrderItem
        data = request.get_json(silent=True) or {}
        count = int(data.get('count', 20))
        import random
        from datetime import datetime, timedelta
        for i in range(count):
            ext = f"SEED-{datetime.utcnow().strftime('%Y%m%d')}-{i:04d}"
            co = CanonOrder(
                user_id=current_user_id,
                channel='meli',
                external_id=ext,
                created_at=(datetime.utcnow() - timedelta(days=random.randint(0,30))).isoformat(),
                status=random.choice(['paid','cancelled','shipped']),
                currency_id='CLP',
                gross_amount=round(random.uniform(5000, 50000), 2),
                net_amount=None,
                buyer_name=random.choice(['Juan','Ana','Pedro','Carla']),
            )
            db.session.add(co)
            db.session.flush()
            for _ in range(random.randint(1,3)):
                it = CanonOrderItem(
                    order_id=co.id,
                    sku=None,
                    title=random.choice(['Producto A','Producto B','Producto C']),
                    quantity=random.randint(1,3),
                    unit_price=round(co.gross_amount / random.randint(1,3), 2)
                )
                db.session.add(it)
        db.session.commit()
        return api_response({"seeded": count}, "Seed created")
    except Exception as e:
        logger.error(f"Seed error: {e}")
        db.session.rollback()
        return api_error("Failed to seed", 500)

# Bank mock endpoints
@app.route('/admin/seed/bank', methods=['POST'])
@jwt_required
def seed_bank():
    try:
        from models import BankTransaction
        current_user_id = get_jwt_identity()
        data = request.get_json(silent=True) or {}
        count = int(data.get('count', 10))
        import random
        from datetime import datetime, timedelta
        for i in range(count):
            tx = BankTransaction(
                user_id=current_user_id,
                account_id='ACC-TEST',
                date=(datetime.utcnow() - timedelta(days=random.randint(0,30))).isoformat(),
                amount=round(random.uniform(5000, 50000), 2) * random.choice([1,1,1,-1]),
                description=random.choice(['Abono Mercado Libre','Transferencia','Pago proveedor','Ajuste']),
                external_id=None,
            )
            db.session.add(tx)
        db.session.commit()
        return api_response({"seeded": count}, "Bank transactions seeded")
    except Exception as e:
        logger.error(f"Seed bank error: {e}")
        db.session.rollback()
        return api_error("Failed to seed bank", 500)

@app.route('/api/bank/transactions', methods=['GET'])
@jwt_required
def list_bank_transactions():
    try:
        from models import BankTransaction
        current_user_id = get_jwt_identity()
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        query = BankTransaction.query.filter_by(user_id=current_user_id)
        if date_from:
            query = query.filter(BankTransaction.date >= date_from)
        if date_to:
            query = query.filter(BankTransaction.date <= date_to)
        rows = query.order_by(BankTransaction.date.desc()).all()
        data = [
            {
                'id': r.id,
                'date': r.date,
                'amount': r.amount,
                'description': r.description,
                'external_id': r.external_id,
            } for r in rows
        ]
        return api_response({"transactions": data, "total": len(data)}, "Bank transactions")
    except Exception as e:
        logger.error(f"List bank error: {e}")
        return api_error("Failed to list bank", 500)

# Conciliation auto (exact amount, date ±2 days)
@app.route('/api/conciliation/auto', methods=['POST'])
@jwt_required
def conciliation_auto():
    try:
        from models import CanonPayout, BankTransaction, Conciliation
        from datetime import datetime, timedelta
        current_user_id = get_jwt_identity()
        # Load all payouts (for simplicity)
        payouts = db.session.execute(
            select(CanonPayout.id, CanonPayout.amount, CanonPayout.paid_out_at).select_from(CanonPayout)
        ).all()
        txs = db.session.execute(
            select(BankTransaction.id, BankTransaction.amount, BankTransaction.date).select_from(BankTransaction).where(BankTransaction.user_id == current_user_id)
        ).all()
        created = 0
        for pid, pamount, pdate in payouts:
            # parse dates
            dtp = None
            try:
                if pdate:
                    dtp = datetime.fromisoformat(pdate.replace('Z','+00:00'))
            except Exception:
                dtp = None
            for tid, tamount, tdate in txs:
                if abs((tamount or 0) - (pamount or 0)) < 0.01:
                    # date tolerance
                    ok_date = True
                    if dtp:
                        try:
                            dtt = datetime.fromisoformat(tdate.replace('Z','+00:00'))
                            ok_date = abs((dtt - dtp).days) <= 2
                        except Exception:
                            ok_date = True
                    exists = Conciliation.query.filter_by(payout_id=pid, bank_transaction_id=tid).first()
                    if not exists and ok_date:
                        c = Conciliation(
                            payout_id=pid,
                            bank_transaction_id=tid,
                            status='conciliated',
                            match_type='exact',
                            diff_amount=0,
                        )
                        db.session.add(c)
                        created += 1
                        break
        db.session.commit()
        return api_response({"created": created}, "Auto conciliation done")
    except Exception as e:
        logger.error(f"Conciliation auto error: {e}")
        db.session.rollback()
        return api_error("Failed to run auto conciliation", 500)

@app.route('/api/conciliation/manual', methods=['POST'])
@jwt_required
def conciliation_manual():
    try:
        from models import Conciliation
        data = request.get_json() or {}
        payout_id = data.get('payout_id')
        bank_tx_id = data.get('bank_transaction_id')
        if not payout_id or not bank_tx_id:
            return api_error("payout_id and bank_transaction_id are required", 400)
        exists = Conciliation.query.filter_by(payout_id=payout_id, bank_transaction_id=bank_tx_id).first()
        if exists:
            return api_response({}, "Already conciliated")
        c = Conciliation(
            payout_id=payout_id,
            bank_transaction_id=bank_tx_id,
            status='manual',
            match_type='manual',
            diff_amount=None,
        )
        db.session.add(c)
        db.session.commit()
        return api_response({}, "Manual conciliation saved")
    except Exception as e:
        logger.error(f"Conciliation manual error: {e}")
        db.session.rollback()
        return api_error("Failed to save manual conciliation", 500)

@app.route('/api/conciliation/kpis', methods=['GET'])
@jwt_required
def conciliation_kpis():
    try:
        from models import Conciliation, CanonPayout
        total_payouts = db.session.execute(select(db.func.count(CanonPayout.id))).scalar() or 0
        total_conc = db.session.execute(select(db.func.count(Conciliation.id))).scalar() or 0
        pct = (total_conc / total_payouts * 100) if total_payouts else 0
        return api_response({"total_payouts": total_payouts, "conciliations": total_conc, "percent": round(pct,2)}, "KPIs")
    except Exception as e:
        logger.error(f"KPIs error: {e}")
        return api_error("Failed to load KPIs", 500)

@app.route('/api/payouts', methods=['GET'])
@jwt_required
def list_payouts():
    try:
        from models import CanonPayout, CanonOrder
        current_user_id = get_jwt_identity()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        q = db.session.query(CanonPayout, CanonOrder).join(CanonOrder, CanonOrder.id == CanonPayout.order_id).filter(CanonOrder.user_id == current_user_id)
        pag = q.paginate(page=page, per_page=per_page, error_out=False)
        data = [
            {
                'payout_id': p.CanonPayout.id if hasattr(p, 'CanonPayout') else p[0].id,
                'amount': (p.CanonPayout.amount if hasattr(p, 'CanonPayout') else p[0].amount),
                'paid_out_at': (p.CanonPayout.paid_out_at if hasattr(p, 'CanonPayout') else p[0].paid_out_at),
                'order_external_id': (p.CanonOrder.external_id if hasattr(p, 'CanonOrder') else p[1].external_id),
                'channel': (p.CanonOrder.channel if hasattr(p, 'CanonOrder') else p[1].channel),
            }
            for p in pag.items
        ]
        return api_response({
            'payouts': data,
            'pagination': {'page': page, 'per_page': per_page, 'total': pag.total, 'pages': pag.pages}
        }, "Payouts list")
    except Exception as e:
        logger.error(f"List payouts error: {e}")
        return api_error("Failed to list payouts", 500)
# Credentials endpoints (BYO)
@app.route('/integrations/meli/credentials', methods=['GET'])
@jwt_required
def get_meli_credentials():
    try:
        current_user_id = get_jwt_identity()
        from models import MercadoLibreCredentials
        creds = MercadoLibreCredentials.query.filter_by(user_id=current_user_id).first()
        if not creds:
            return api_response({"credentials": None}, "No credentials configured")
        return api_response({"credentials": creds.to_safe_dict()}, "Credentials loaded")
    except Exception as e:
        logger.error(f"Get creds error: {e}")
        return api_error("Failed to get credentials", 500)

@app.route('/integrations/meli/credentials', methods=['POST'])
@jwt_required
def upsert_meli_credentials():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json() or {}
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        redirect_uri = data.get('redirect_uri')
        site_id = data.get('site_id', 'MLC')
        if not client_id or not client_secret or not redirect_uri:
            return api_error("client_id, client_secret and redirect_uri are required", 400)
        from models import MercadoLibreCredentials
        creds = MercadoLibreCredentials.query.filter_by(user_id=current_user_id).first()
        if not creds:
            creds = MercadoLibreCredentials(
                user_id=current_user_id,
                client_id=client_id,
                site_id=site_id,
                redirect_uri=redirect_uri,
                client_secret_encrypted="",
            )
            db.session.add(creds)
        else:
            creds.client_id = client_id
            creds.site_id = site_id
            creds.redirect_uri = redirect_uri
        creds.set_client_secret(client_secret)
        db.session.commit()
        return api_response({"credentials": creds.to_safe_dict()}, "Credentials saved")
    except Exception as e:
        logger.error(f"Upsert creds error: {e}")
        db.session.rollback()
        return api_error("Failed to save credentials", 500)

@app.route('/integrations/meli/credentials', methods=['DELETE'])
@jwt_required
def delete_meli_credentials():
    try:
        current_user_id = get_jwt_identity()
        from models import MercadoLibreCredentials
        creds = MercadoLibreCredentials.query.filter_by(user_id=current_user_id).first()
        if creds:
            db.session.delete(creds)
            db.session.commit()
        return api_response({}, "Credentials deleted")
    except Exception as e:
        logger.error(f"Delete creds error: {e}")
        db.session.rollback()
        return api_error("Failed to delete credentials", 500)

@app.route('/integrations/meli/account', methods=['DELETE'])
@jwt_required
def delete_meli_account():
    try:
        current_user_id = get_jwt_identity()
        from models import MercadoLibreAccount
        acc = MercadoLibreAccount.query.filter_by(user_id=current_user_id).first()
        if acc:
            db.session.delete(acc)
            db.session.commit()
        return api_response({}, "Account tokens deleted")
    except Exception as e:
        logger.error(f"Delete account error: {e}")
        db.session.rollback()
        return api_error("Failed to delete account", 500)

# Falabella credentials endpoints (BYO)
@app.route('/integrations/falabella/credentials', methods=['GET'])
@jwt_required
def get_falabella_creds():
    try:
        current_user_id = get_jwt_identity()
        from models import FalabellaCredentials
        creds = FalabellaCredentials.query.filter_by(user_id=current_user_id).first()
        if not creds:
            return api_response({"credentials": None}, "No credentials configured")
        return api_response({"credentials": creds.to_safe_dict()}, "Credentials loaded")
    except Exception as e:
        logger.error(f"Get falabella creds error: {e}")
        return api_error("Failed to get Falabella credentials", 500)

@app.route('/integrations/falabella/credentials', methods=['POST'])
@jwt_required
def upsert_falabella_creds():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json() or {}
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')
        api_base_url = data.get('api_base_url')
        if not client_id or not client_secret:
            return api_error("client_id and client_secret are required", 400)
        from models import FalabellaCredentials
        creds = FalabellaCredentials.query.filter_by(user_id=current_user_id).first()
        if not creds:
            creds = FalabellaCredentials(
                user_id=current_user_id,
                client_id=client_id,
                api_base_url=api_base_url,
                client_secret_encrypted="",
            )
            db.session.add(creds)
        else:
            creds.client_id = client_id
            creds.api_base_url = api_base_url
        creds.set_client_secret(client_secret)
        db.session.commit()
        return api_response({"credentials": creds.to_safe_dict()}, "Falabella credentials saved")
    except Exception as e:
        logger.error(f"Upsert falabella creds error: {e}")
        db.session.rollback()
        return api_error("Failed to save Falabella credentials", 500)

# Webhook endpoint for Mercado Libre notifications (validation-friendly)
@app.route('/webhooks/meli', methods=['GET', 'POST'])
@app.route('/webhooks/meli/', methods=['GET', 'POST'])
def meli_webhook():
    try:
        if request.method == 'GET':
            # Some providers verify by hitting the URL; respond 200 OK
            return "ok", 200
        payload = request.get_json(silent=True) or {}
        logger.info(f"MELI webhook received: {payload}")
        # TODO: queue processing if needed
        return "ok", 200
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return "error", 200  # still 200 to pass provider validation

# Frontend static files
@app.route('/assets/<path:path>')
def serve_static(path):
    """Serve static files from frontend build."""
    try:
        return send_from_directory('frontend/dist/assets', path)
    except FileNotFoundError:
        return api_error("Static file not found", 404)

# Root route to serve React frontend
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path=''):
    """Serve React frontend."""
    # Skip API routes
    if path.startswith('api/') or path.startswith('auth/') or path.startswith('health'):
        return api_error("API endpoint not found", 404)
    
    try:
        # Try to serve the built React app first
        return send_file('frontend/dist/index.html')
    except FileNotFoundError:
        # Fallback to status page if frontend not built
        return """
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SalesHarmony</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 2rem; background: #f5f5f5; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; }
                .status { padding: 1rem; margin: 1rem 0; border-radius: 4px; }
                .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
                .warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
                h1 { color: #333; }
                ul { list-style-type: none; padding: 0; }
                li { padding: 0.5rem 0; border-bottom: 1px solid #eee; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 SalesHarmony Backend</h1>
                <div class="status success">
                    <strong>✅ Backend is running!</strong>
                </div>
                <div class="status warning">
                    <strong>⚠️ Frontend not built yet</strong><br>
                    React frontend will be connected soon.
                </div>
                <h2>Available Endpoints:</h2>
                <ul>
                    <li><strong>GET /health</strong> - Health check</li>
                    <li><strong>POST /auth/register</strong> - Register user</li>
                    <li><strong>POST /auth/login</strong> - Login user</li>
                    <li><strong>GET /auth/me</strong> - Get current user</li>
                    <li><strong>GET /api/sales</strong> - Get sales data</li>
                    <li><strong>POST /api/sales</strong> - Create sale</li>
                </ul>
                <p><em>JWT Available: """ + str(JWT_AVAILABLE) + """</em></p>
            </div>
        </body>
        </html>
        """
    except Exception as e:
        logger.error(f"Frontend serve error: {e}")
        return api_error("Internal server error", 500)

# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return api_error("Bad request", 400)

@app.errorhandler(401) 
def unauthorized(error):
    return api_error("Unauthorized", 401)

@app.errorhandler(404)
def not_found(error):
    return api_error("Not found", 404)

@app.errorhandler(500)
def internal_error(error):
    return api_error("Internal server error", 500)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)