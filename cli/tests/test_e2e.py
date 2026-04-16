import base64
import json
import os
import uuid

import pytest
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

from secure_message_cli import (
    _b64encode,
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


def _encrypt_message_v2_for_recipients(
    plaintext: str,
    recipients: list[tuple[str, x25519.X25519PublicKey]],
) -> tuple[str, str, str]:
    message_key = AESGCM.generate_key(bit_length=256)
    iv = os.urandom(12)
    ciphertext = AESGCM(message_key).encrypt(iv, plaintext.encode("utf-8"), None)

    copies: dict[str, dict[str, str]] = {}
    for username, recipient_public in recipients:
        eph_private = x25519.X25519PrivateKey.generate()
        eph_public = eph_private.public_key()
        shared = eph_private.exchange(recipient_public)
        salt = os.urandom(16)
        wrap_iv = os.urandom(12)
        wrapping_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"secure-message-key-wrap-v2",
        ).derive(shared)
        wrapped_key = AESGCM(wrapping_key).encrypt(wrap_iv, message_key, None)

        copies[username] = {
            "epk": _b64encode(
                eph_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ),
            "salt": _b64encode(salt),
            "iv": _b64encode(wrap_iv),
            "key": _b64encode(wrapped_key),
        }

    return json.dumps({"v": 2, "copies": copies}), _b64encode(ciphertext), _b64encode(iv)


def _file_envelope(filename: str = "evidence.bin", caption: str = "test file") -> dict:
    file_bytes = b"worker4-test-file-payload"
    return {
        "kind": "file",
        "caption": caption,
        "attachment": {
            "name": filename,
            "mime": "application/octet-stream",
            "bytes_b64": base64.b64encode(file_bytes).decode("ascii"),
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

    envelope = _file_envelope()
    encrypted_key, ciphertext, iv = _encrypt_message(json.dumps(envelope), recipient_public_b64)
    decrypted_attachment = _decrypt_message(ciphertext, iv, encrypted_key, recipient_private)
    decoded = json.loads(decrypted_attachment)

    assert decoded["kind"] == "file"
    assert decoded["caption"] == envelope["caption"]
    assert decoded["attachment"]["name"] == envelope["attachment"]["name"]
    assert decoded["attachment"]["mime"] == envelope["attachment"]["mime"]
    assert base64.b64decode(decoded["attachment"]["bytes_b64"]) == base64.b64decode(
        envelope["attachment"]["bytes_b64"]
    )


def test_cli_can_decrypt_frontend_v2_message_format():
    recipient_private, recipient_public = _generate_keypair()
    sender_private, sender_public = _generate_keypair()

    plaintext = "frontend v2 payload"
    encrypted_key, ciphertext, iv = _encrypt_message_v2_for_recipients(
        plaintext,
        [
            ("recipient", recipient_public),
            ("sender", sender_public),
        ],
    )

    decrypted = _decrypt_message(
        ciphertext,
        iv,
        encrypted_key,
        recipient_private,
        "recipient",
    )
    assert decrypted == plaintext


@pytest.mark.e2e
def test_e2e_file_attachment_flow_preserves_text_message_compatibility():
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

    attachment_plaintext = json.dumps(_file_envelope(caption="release artifact"))
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
    assert attachment["kind"] == "file"
    assert attachment["caption"] == "release artifact"
    assert attachment["attachment"]["mime"] == "application/octet-stream"
    assert base64.b64decode(attachment["attachment"]["bytes_b64"]) == b"worker4-test-file-payload"
