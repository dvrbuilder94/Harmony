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
        client_id = os.environ.get('MELI_CLIENT_ID')
        redirect_uri = os.environ.get('MELI_REDIRECT_URI')
        if not client_id or not redirect_uri:
            return api_error("MELI_CLIENT_ID and MELI_REDIRECT_URI are required", 500)
        current_user_id = get_jwt_identity()
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

        client_id = os.environ.get('MELI_CLIENT_ID')
        client_secret = os.environ.get('MELI_CLIENT_SECRET')
        redirect_uri = os.environ.get('MELI_REDIRECT_URI')
        if not client_id or not client_secret or not redirect_uri:
            return api_error("MELI env vars missing", 500)

        # Verify state and extract user id
        try:
            state_payload = decode_state_token(state)
            target_user_id = state_payload.get('user_id')
            if not target_user_id:
                return api_error("Invalid state payload", 400)
        except Exception as e:
            logger.error(f"Invalid state: {e}")
            return api_error("Invalid state", 400)

        token_res = requests.post(
            "https://api.mercadolibre.com/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
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
        from models import MercadoLibreAccount, MLOrder, MLOrderItem

        account = MercadoLibreAccount.query.filter_by(user_id=current_user_id).first()
        if not account:
            return api_error("No Mercado Libre account linked", 400)

        # Refresh token if expired and we have refresh_token
        if getattr(account, 'token_expires_at', None) and account.token_expires_at <= datetime.utcnow():
            if account.refresh_token:
                client_id = os.environ.get('MELI_CLIENT_ID')
                client_secret = os.environ.get('MELI_CLIENT_SECRET')
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
                    headers={"Accept": "application/json"},
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

        # Get recent orders (last 7 days) - simplified
        created_from = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        orders_url = f"https://api.mercadolibre.com/orders/search/recent?seller={account.meli_user_id}&order.date_created.from={created_from}"
        res = requests.get(orders_url, headers=headers, timeout=30)
        if res.status_code != 200:
            return api_error("Failed to fetch orders from Mercado Libre", 502, details=res.text)
        data = res.json()
        results = data.get('results', [])

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

        db.session.commit()
        return api_response({"saved": saved, "fetched": len(results)}, "Mercado Libre sync persisted orders")
    except Exception as e:
        logger.error(f"MELI sync error: {e}")
        return api_error("Failed to sync Mercado Libre orders", 500)

# Unified orders endpoint
@app.route('/api/orders', methods=['GET'])
@jwt_required
def list_orders():
    try:
        current_user_id = get_jwt_identity()
        from models import MLOrder

        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        status = request.args.get('status')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')

        query = MLOrder.query.filter_by(user_id=current_user_id)
        if status:
            query = query.filter(MLOrder.status == status)
        if date_from:
            query = query.filter(MLOrder.date_created >= date_from)
        if date_to:
            query = query.filter(MLOrder.date_created <= date_to)

        orders = query.order_by(MLOrder.date_created.desc()).paginate(page=page, per_page=per_page, error_out=False)
        data = [o.to_dict(include_items=False) for o in orders.items]
        return api_response({
            "orders": data,
            "pagination": {"page": page, "per_page": per_page, "total": orders.total, "pages": orders.pages}
        })
    except Exception as e:
        logger.error(f"List orders error: {e}")
        return api_error("Failed to list orders", 500)

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