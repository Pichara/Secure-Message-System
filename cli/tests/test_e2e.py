import os
import uuid

import pytest
import requests

from secure_message_cli import (
    _decrypt_message,
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


@pytest.mark.e2e
def test_e2e_message_flow():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    user_a = f"alice_{uuid.uuid4().hex[:8]}"
    user_b = f"bob_{uuid.uuid4().hex[:8]}"

    password_a = "Password!123"
    password_b = "Password!123"

    # Register user A
    priv_a, pub_a = _generate_keypair()
    payload_a = {
        "username": user_a,
        "password": password_a,
        "public_key": _serialize_public_key(pub_a),
        "encrypted_private_key": _encrypt_private_key(_serialize_private_key(priv_a), password_a),
    }
    resp = requests.post(f"{BACKEND_URL}/api/register", json=payload_a, timeout=10)
    assert resp.status_code == 201

    # Register user B
    priv_b, pub_b = _generate_keypair()
    payload_b = {
        "username": user_b,
        "password": password_b,
        "public_key": _serialize_public_key(pub_b),
        "encrypted_private_key": _encrypt_private_key(_serialize_private_key(priv_b), password_b),
    }
    resp = requests.post(f"{BACKEND_URL}/api/register", json=payload_b, timeout=10)
    assert resp.status_code == 201

    # Login as A
    resp = requests.post(
        f"{BACKEND_URL}/api/login",
        json={"username": user_a, "password": password_a},
        timeout=10,
    )
    assert resp.status_code == 200
    token_a = resp.json()["token"]

    # Fetch B public key
    resp = requests.get(
        f"{BACKEND_URL}/api/users/{user_b}/public-key",
        headers={"Authorization": f"Bearer {token_a}"},
        timeout=10,
    )
    assert resp.status_code == 200
    pub_b_b64 = resp.json()["public_key"]

    # Send message from A -> B
    plaintext = "hello from test"
    encrypted_key, ciphertext, iv = _encrypt_message(plaintext, pub_b_b64)
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

    # Login as B
    resp = requests.post(
        f"{BACKEND_URL}/api/login",
        json={"username": user_b, "password": password_b},
        timeout=10,
    )
    assert resp.status_code == 200
    token_b = resp.json()["token"]

    # Fetch messages for B with A
    resp = requests.get(
        f"{BACKEND_URL}/api/messages?with={user_a}",
        headers={"Authorization": f"Bearer {token_b}"},
        timeout=10,
    )
    assert resp.status_code == 200
    messages = resp.json()
    assert len(messages) >= 1

    last_msg = messages[-1]
    decrypted = _decrypt_message(
        last_msg["ciphertext"],
        last_msg["iv"],
        last_msg["encrypted_key"],
        priv_b,
    )
    assert decrypted == plaintext
