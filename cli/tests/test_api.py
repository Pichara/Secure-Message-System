import os
import subprocess
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


def _register_payload(username: str, password: str) -> tuple[dict, object, object]:
    priv, pub = _generate_keypair()
    return (
        {
            "username": username,
            "password": password,
            "public_key": _serialize_public_key(pub),
            "encrypted_private_key": _encrypt_private_key(_serialize_private_key(priv), password),
        },
        priv,
        pub,
    )


def _register_user(username: str, password: str):
    payload, priv, pub = _register_payload(username, password)
    resp = requests.post(f"{BACKEND_URL}/api/register", json=payload, timeout=10)
    assert resp.status_code == 201
    return priv, pub


def _register_raw(username: str, password: str) -> requests.Response:
    payload, _, _ = _register_payload(username, password)
    return requests.post(f"{BACKEND_URL}/api/register", json=payload, timeout=10)


def _database_url() -> str | None:
    return os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")


def _promote_user_to_admin(username: str) -> None:
    database_url = _database_url()
    if database_url:
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError:
            try:
                import psycopg2  # type: ignore[import-not-found]
            except ImportError:
                pass
            else:
                try:
                    conn = psycopg2.connect(database_url)
                except Exception:
                    pass
                else:
                    try:
                        with conn:
                            with conn.cursor() as cur:
                                cur.execute("UPDATE users SET role = 'admin' WHERE username = %s", (username,))
                                assert cur.rowcount == 1
                    finally:
                        conn.close()
                    return
        else:
            try:
                with psycopg.connect(database_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE users SET role = 'admin' WHERE username = %s", (username,))
                        assert cur.rowcount == 1
            except Exception:
                pass
            else:
                return

    escaped_username = username.replace("'", "''")
    command = [
        "docker",
        "exec",
        "secure-message-db",
        "psql",
        "-U",
        "postgres",
        "-d",
        "secure_message",
        "-c",
        f"UPDATE users SET role = 'admin' WHERE username = '{escaped_username}';",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.skip(
            "No TEST_DATABASE_URL/DATABASE_URL for direct DB access and Docker fallback failed: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    assert "UPDATE 1" in result.stdout


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


def _fetch_me(token: str) -> dict:
    resp = requests.get(f"{BACKEND_URL}/api/me", headers=_auth_headers(token), timeout=10)
    assert resp.status_code == 200
    return resp.json()


def _save_contact(token: str, alias: str, username: str) -> requests.Response:
    return requests.post(
        f"{BACKEND_URL}/api/contacts",
        headers=_auth_headers(token),
        json={"alias": alias, "username": username},
        timeout=10,
    )


@pytest.mark.e2e
def test_api_docs_available():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    resp = requests.get(f"{BACKEND_URL}/openapi.json", timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("openapi") is not None

    resp = requests.get(f"{BACKEND_URL}/api/docs", timeout=10)
    assert resp.status_code == 200
    assert "openapi" in resp.text.lower()
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]


@pytest.mark.e2e
def test_api_cors_defaults_allow_localhost_and_reject_untrusted_origin():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    allowed = requests.options(
        f"{BACKEND_URL}/api/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
        },
        timeout=10,
    )
    assert allowed.status_code == 204
    assert allowed.headers["Access-Control-Allow-Origin"] == "http://localhost:5173"

    blocked = requests.options(
        f"{BACKEND_URL}/api/login",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
        timeout=10,
    )
    assert blocked.status_code == 403
    assert blocked.json()["error"] == "cors_denied"


@pytest.mark.e2e
def test_api_auth_and_logout():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    username = f"apiuser_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(username, password)
    token = _login(username, password)

    me = _fetch_me(token)
    assert me["username"] == username
    assert "public_key" in me
    assert "encrypted_private_key" in me

    logout_resp = requests.post(
        f"{BACKEND_URL}/api/logout",
        headers=_auth_headers(token),
        timeout=10,
    )
    assert logout_resp.status_code == 200

    me_after = requests.get(
        f"{BACKEND_URL}/api/me",
        headers=_auth_headers(token),
        timeout=10,
    )
    assert me_after.status_code == 401


@pytest.mark.e2e
def test_api_register_enforces_stronger_password_policy():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    weak_passwords = [
        ("password!", "number"),
        ("Password123", "special"),
        ("Pw1!", "8-128"),
    ]

    for password, expected_hint in weak_passwords:
        username = f"weak_{uuid.uuid4().hex[:8]}"
        resp = _register_raw(username, password)
        assert resp.status_code == 400
        payload = resp.json()
        assert payload["error"] == "invalid_password"
        message = payload.get("message", "").lower()
        assert "password" in message
        assert expected_hint in message

    strong_username = f"strong_{uuid.uuid4().hex[:8]}"
    strong_resp = _register_raw(strong_username, "Password!123")
    assert strong_resp.status_code == 201


@pytest.mark.e2e
def test_api_me_includes_role_for_standard_user():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    username = f"roleuser_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(username, password)
    token = _login(username, password)
    me = _fetch_me(token)

    assert me["username"] == username
    assert me["role"] == "user"
    assert "public_key" in me
    assert "encrypted_private_key" in me


@pytest.mark.e2e
def test_api_contacts_are_saved_per_user_in_backend():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    owner = f"owner_{uuid.uuid4().hex[:8]}"
    contact_user = f"friend_{uuid.uuid4().hex[:8]}"
    outsider = f"outsider_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(owner, password)
    _register_user(contact_user, password)
    _register_user(outsider, password)

    owner_token = _login(owner, password)
    outsider_token = _login(outsider, password)

    save_resp = _save_contact(owner_token, "friend", contact_user)
    assert save_resp.status_code == 201

    list_resp = requests.get(
        f"{BACKEND_URL}/api/contacts",
        headers=_auth_headers(owner_token),
        timeout=10,
    )
    assert list_resp.status_code == 200
    assert list_resp.json() == [{"alias": "friend", "username": contact_user}]

    outsider_list = requests.get(
        f"{BACKEND_URL}/api/contacts",
        headers=_auth_headers(outsider_token),
        timeout=10,
    )
    assert outsider_list.status_code == 200
    assert outsider_list.json() == []

    delete_resp = requests.delete(
        f"{BACKEND_URL}/api/contacts/friend",
        headers=_auth_headers(owner_token),
        timeout=10,
    )
    assert delete_resp.status_code == 200

    list_after = requests.get(
        f"{BACKEND_URL}/api/contacts",
        headers=_auth_headers(owner_token),
        timeout=10,
    )
    assert list_after.status_code == 200
    assert list_after.json() == []


@pytest.mark.e2e
def test_api_admin_user_listing_requires_admin_and_returns_usernames_only():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    admin_username = f"admin_{uuid.uuid4().hex[:8]}"
    member_username = f"member_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(admin_username, password)
    _register_user(member_username, password)
    _promote_user_to_admin(admin_username)

    member_token = _login(member_username, password)
    forbidden = requests.get(
        f"{BACKEND_URL}/api/admin/users",
        headers=_auth_headers(member_token),
        timeout=10,
    )
    assert forbidden.status_code == 403

    unauthorized = requests.get(f"{BACKEND_URL}/api/admin/users", timeout=10)
    assert unauthorized.status_code == 401

    admin_token = _login(admin_username, password)
    me = _fetch_me(admin_token)
    assert me["role"] == "admin"

    resp = requests.get(
        f"{BACKEND_URL}/api/admin/users",
        headers=_auth_headers(admin_token),
        timeout=10,
    )
    assert resp.status_code == 200

    payload = resp.json()
    assert set(payload.keys()) == {"users"}
    usernames = [user["username"] for user in payload["users"]]
    assert len(usernames) == len(set(usernames))
    assert admin_username in usernames
    assert member_username in usernames
    for user in payload["users"]:
        assert set(user.keys()) == {"username"}


@pytest.mark.e2e
def test_api_admin_can_delete_non_admin_users_and_revoke_their_token():
    if not _health_check():
        pytest.skip("Backend is not reachable")

    admin_username = f"admin_{uuid.uuid4().hex[:8]}"
    member_username = f"member_{uuid.uuid4().hex[:8]}"
    password = "Password!123"

    _register_user(admin_username, password)
    _register_user(member_username, password)
    _promote_user_to_admin(admin_username)

    admin_token = _login(admin_username, password)
    member_token = _login(member_username, password)

    forbidden = requests.delete(
        f"{BACKEND_URL}/api/admin/users/{member_username}",
        headers=_auth_headers(member_token),
        timeout=10,
    )
    assert forbidden.status_code == 403

    deleted = requests.delete(
        f"{BACKEND_URL}/api/admin/users/{member_username}",
        headers=_auth_headers(admin_token),
        timeout=10,
    )
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"

    login_after = requests.post(
        f"{BACKEND_URL}/api/login",
        json={"username": member_username, "password": password},
        timeout=10,
    )
    assert login_after.status_code == 401

    me_after = requests.get(
        f"{BACKEND_URL}/api/me",
        headers=_auth_headers(member_token),
        timeout=10,
    )
    assert me_after.status_code == 401

    cannot_delete_self = requests.delete(
        f"{BACKEND_URL}/api/admin/users/{admin_username}",
        headers=_auth_headers(admin_token),
        timeout=10,
    )
    assert cannot_delete_self.status_code == 400


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
        headers=_auth_headers(token_a),
        timeout=10,
    )
    assert resp.status_code == 200
    pub_b = resp.json()["public_key"]

    ids = []
    for idx in range(2):
        encrypted_key, ciphertext, iv = _encrypt_message(f"hello {idx}", pub_b)
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
        ids.append(resp.json()["id"])

    latest_id = max(ids)
    older_id = min(ids)

    resp = requests.get(
        f"{BACKEND_URL}/api/messages?with={user_a}&limit=1&order=desc",
        headers=_auth_headers(token_b),
        timeout=10,
    )
    assert resp.status_code == 200
    messages = resp.json()
    assert len(messages) == 1
    assert messages[0]["id"] == latest_id

    resp = requests.get(
        f"{BACKEND_URL}/api/messages?with={user_a}&limit=1&order=desc&before_id={latest_id}",
        headers=_auth_headers(token_b),
        timeout=10,
    )
    assert resp.status_code == 200
    messages = resp.json()
    assert len(messages) == 1
    assert messages[0]["id"] == older_id
