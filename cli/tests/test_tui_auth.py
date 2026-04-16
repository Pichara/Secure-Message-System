import tui_app
from tui_app import AuthScreen


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or ""

    def json(self):
        return self._payload


def test_admin_login_does_not_require_private_key_decryption(monkeypatch):
    screen = AuthScreen()
    state = {"backend_url": "http://localhost:8080"}

    monkeypatch.setattr(tui_app, "_state", lambda: state)
    monkeypatch.setattr(tui_app, "_backend_url", lambda current_state: current_state["backend_url"])
    monkeypatch.setattr(tui_app, "_save_state", lambda current_state: None)

    def fake_request(method: str, url: str, token=None, **kwargs):
        if method == "POST" and url.endswith("/api/login"):
            return _FakeResponse(200, {"token": "token-123", "expires_in": 3600, "role": "admin"})
        if method == "GET" and url.endswith("/api/me"):
            assert token == "token-123"
            return _FakeResponse(
                200,
                {
                    "username": "ADMIN",
                    "role": "admin",
                    "public_key": "public",
                    "encrypted_private_key": "{\"ciphertext\":\"\",\"salt\":\"\",\"nonce\":\"\"}",
                },
            )
        raise AssertionError(f"Unexpected request: {method} {url}")

    def fail_load_private_key(current_state, password):
        raise AssertionError("Admin login should not try to decrypt a local private key.")

    monkeypatch.setattr(tui_app, "_request", fake_request)
    monkeypatch.setattr(tui_app, "_load_private_key_from_state", fail_load_private_key)

    auth = screen._login("ADMIN", "Secure123!")

    assert auth is not None
    assert auth.username == "ADMIN"
    assert auth.role == "admin"
    assert auth.private_key is None
