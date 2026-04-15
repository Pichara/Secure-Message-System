import base64
import json
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


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _image_envelope(filename: str = "photo.png", caption: str = "test image") -> dict:
    image_bytes = b"\x89PNG\r\n\x1a\nworker4-test-image"
    return {
        "kind": "image",
        "caption": caption,
        "attachment": {
            "name": filename,
            "mime": "image/png",
            "bytes_b64": base64.b64encode(image_bytes).decode("ascii"),
        },
    }


@pytest.mark.e2e
def test_e2e_text_message_flow():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    user_a = f"alice_{uuid.uuid4().hex[:8]}"
    user_b = f"bob_{uuid.uuid4().hex[:8]}"

    password_a = "Password!123"
    password_b = "Password!123"

    _register_user(user_a, password_a)
    priv_b, _ = _register_user(user_b, password_b)

    token_a = _login(user_a, password_a)

    resp = requests.get(
        f"{BACKEND_URL}/api/users/{user_b}/public-key",
        headers=_auth_headers(token_a),
        timeout=10,
    )
    assert resp.status_code == 200
    pub_b_b64 = resp.json()["public_key"]

    plaintext = "hello from test"
    encrypted_key, ciphertext, iv = _encrypt_message(plaintext, pub_b_b64)
    resp = requests.post(
        f"{BACKEND_URL}/api/messages",
        headers=_auth_headers(token_a),
        json={
            "recipient": user_b,
            "encrypted_key": encrypted_key,
            "ciphertext": ciphertext,
            "iv": iv,
        },
        timeout=10,
    )
    assert resp.status_code == 201

    token_b = _login(user_b, password_b)

    resp = requests.get(
        f"{BACKEND_URL}/api/messages?with={user_a}",
        headers=_auth_headers(token_b),
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


def test_attachment_envelope_round_trip_preserves_text_compatibility():
    recipient_private, recipient_public = _generate_keypair()
    recipient_public_b64 = _serialize_public_key(recipient_public)

    legacy_text = "plain text still decrypts"
    encrypted_key, ciphertext, iv = _encrypt_message(legacy_text, recipient_public_b64)
    decrypted_text = _decrypt_message(ciphertext, iv, encrypted_key, recipient_private)
    assert decrypted_text == legacy_text

    envelope = _image_envelope()
    encrypted_key, ciphertext, iv = _encrypt_message(json.dumps(envelope), recipient_public_b64)
    decrypted_attachment = _decrypt_message(ciphertext, iv, encrypted_key, recipient_private)
    decoded = json.loads(decrypted_attachment)

    assert decoded["kind"] == "image"
    assert decoded["caption"] == envelope["caption"]
    assert decoded["attachment"]["name"] == envelope["attachment"]["name"]
    assert decoded["attachment"]["mime"] == envelope["attachment"]["mime"]
    assert base64.b64decode(decoded["attachment"]["bytes_b64"]) == base64.b64decode(
        envelope["attachment"]["bytes_b64"]
    )


@pytest.mark.e2e
def test_e2e_image_attachment_flow_preserves_text_message_compatibility():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    sender = f"sender_{uuid.uuid4().hex[:8]}"
    recipient = f"recipient_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(sender, password)
    recipient_private, _ = _register_user(recipient, password)

    sender_token = _login(sender, password)
    recipient_token = _login(recipient, password)

    resp = requests.get(
        f"{BACKEND_URL}/api/users/{recipient}/public-key",
        headers=_auth_headers(sender_token),
        timeout=10,
    )
    assert resp.status_code == 200
    recipient_public_b64 = resp.json()["public_key"]

    text_plaintext = "legacy text payload"
    encrypted_key, ciphertext, iv = _encrypt_message(text_plaintext, recipient_public_b64)
    resp = requests.post(
        f"{BACKEND_URL}/api/messages",
        headers=_auth_headers(sender_token),
        json={
            "recipient": recipient,
            "encrypted_key": encrypted_key,
            "ciphertext": ciphertext,
            "iv": iv,
        },
        timeout=10,
    )
    assert resp.status_code == 201

    attachment_plaintext = json.dumps(_image_envelope(caption="release screenshot"))
    encrypted_key, ciphertext, iv = _encrypt_message(attachment_plaintext, recipient_public_b64)
    resp = requests.post(
        f"{BACKEND_URL}/api/messages",
        headers=_auth_headers(sender_token),
        json={
            "recipient": recipient,
            "encrypted_key": encrypted_key,
            "ciphertext": ciphertext,
            "iv": iv,
        },
        timeout=10,
    )
    assert resp.status_code == 201

    resp = requests.get(
        f"{BACKEND_URL}/api/messages?with={sender}&order=asc",
        headers=_auth_headers(recipient_token),
        timeout=10,
    )
    assert resp.status_code == 200
    messages = resp.json()
    assert len(messages) >= 2

    decrypted_payloads = [
        _decrypt_message(message["ciphertext"], message["iv"], message["encrypted_key"], recipient_private)
        for message in messages[-2:]
    ]

    assert decrypted_payloads[0] == text_plaintext
    attachment = json.loads(decrypted_payloads[1])
    assert attachment["kind"] == "image"
    assert attachment["caption"] == "release screenshot"
    assert attachment["attachment"]["mime"] == "image/png"
    assert base64.b64decode(attachment["attachment"]["bytes_b64"]).startswith(b"\x89PNG\r\n\x1a\n")
