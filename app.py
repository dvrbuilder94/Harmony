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

# Configure CORS
CORS(app, 
     origins=[
         "http://localhost:3000",
         "http://127.0.0.1:3000",
         "http://localhost:5173",
         "http://127.0.0.1:5173",
     ],
     allow_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

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