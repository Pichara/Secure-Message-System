import os
import uuid

import pytest
import requests

from secure_message_cli import (
    _encrypt_message,
    _encrypt_private_key,
    _generate_keypair,
    _serialize_private_key,
    _serialize_public_key,
)

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8080")


def _health_check():
    try:
        resp = requests.get(f"{BACKEND_URL}/health", timeout=3)
    except Exception:
        return False
    return resp.status_code == 200


def _register_user(username: str, password: str):
    priv, pub = _generate_keypair()
    payload = {
        "username": username,
        "password": password,
        "public_key": _serialize_public_key(pub),
        "encrypted_private_key": _encrypt_private_key(_serialize_private_key(priv), password),
    }
    resp = requests.post(f"{BACKEND_URL}/api/register", json=payload, timeout=10)
    assert resp.status_code == 201
    return priv, pub


def _login(username: str, password: str) -> str:
    resp = requests.post(
        f"{BACKEND_URL}/api/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    assert resp.status_code == 200
    return resp.json()["token"]


@pytest.mark.e2e
def test_api_auth_and_logout():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    username = f"apiuser_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(username, password)
    token = _login(username, password)

    me_resp = requests.get(
        f"{BACKEND_URL}/api/me",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert me_resp.status_code == 200
    me = me_resp.json()
    assert me["username"] == username
    assert "public_key" in me
    assert "encrypted_private_key" in me

    logout_resp = requests.post(
        f"{BACKEND_URL}/api/logout",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert logout_resp.status_code == 200

    me_after = requests.get(
        f"{BACKEND_URL}/api/me",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    assert me_after.status_code == 401


@pytest.mark.e2e
def test_api_messages_limit_and_order():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    user_a = f"apialice_{uuid.uuid4().hex[:8]}"
    user_b = f"apibob_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(user_a, password)
    _register_user(user_b, password)

    token_a = _login(user_a, password)
    token_b = _login(user_b, password)

    resp = requests.get(
        f"{BACKEND_URL}/api/users/{user_b}/public-key",
        headers={"Authorization": f"Bearer {token_a}"},
        timeout=10,
    )
    assert resp.status_code == 200
    pub_b = resp.json()["public_key"]

    ids = []
    for idx in range(2):
        encrypted_key, ciphertext, iv = _encrypt_message(f"hello {idx}", pub_b)
        resp = requests.post(
            f"{BACKEND_URL}/api/messages",
            headers={"Authorization": f"Bearer {token_a}"},
            json={
                "recipient": user_b,
                "encrypted_key": encrypted_key,
                "ciphertext": ciphertext,
                "iv": iv,
            },
            timeout=10,
        )
        assert resp.status_code == 201
        ids.append(resp.json()["id"])

    latest_id = max(ids)
    older_id = min(ids)

    resp = requests.get(
        f"{BACKEND_URL}/api/messages?with={user_a}&limit=1&order=desc",
        headers={"Authorization": f"Bearer {token_b}"},
        timeout=10,
    )
    assert resp.status_code == 200
    messages = resp.json()
    assert len(messages) == 1
    assert messages[0]["id"] == latest_id

    resp = requests.get(
        f"{BACKEND_URL}/api/messages?with={user_a}&limit=1&order=desc&before_id={latest_id}",
        headers={"Authorization": f"Bearer {token_b}"},
        timeout=10,
    )
    assert resp.status_code == 200
    messages = resp.json()
    assert len(messages) == 1
    assert messages[0]["id"] == older_id
