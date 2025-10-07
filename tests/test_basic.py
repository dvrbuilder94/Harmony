import os
import sys
import json
import pytest

os.environ.setdefault("SESSION_SECRET", "test_secret")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

# Ensure project root is importable
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app, db  # noqa: E402


@pytest.fixture(autouse=True)
def app_ctx():
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield


def test_health(client=None):
    client = app.test_client()
    res = client.get('/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert data["data"]["status"] == "healthy"


def test_auth_flow():
    client = app.test_client()
    # Register
    res = client.post('/auth/register', json={
        "email": "test@example.com",
        "password": "secret",
        "name": "Tester"
    })
    assert res.status_code == 201

    # Login should fail until email verified
    res = client.post('/auth/login', json={
        "email": "test@example.com",
        "password": "secret"
    })
    assert res.status_code == 401

    # Generate verification token using server helper
    from app import create_email_verification_token
    token = create_email_verification_token('dummy', 'dummy@example.com')  # placeholder
    # But we need real user's token; fetch user id from DB
    from models import User, db
    u = User.query.filter_by(email='test@example.com').first()
    assert u is not None
    token = create_email_verification_token(u.id, u.email)

    # Verify email
    res = client.post('/auth/verify-email', json={"token": token})
    assert res.status_code == 200

    # Login again
    res = client.post('/auth/login', json={
        "email": "test@example.com",
        "password": "secret"
    })
    assert res.status_code == 200
    token = res.get_json()["data"]["access_token"]
    assert token

    # Me
    res = client.get('/auth/me', headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    me = res.get_json()["data"]
    assert me["email"] == "test@example.com"

