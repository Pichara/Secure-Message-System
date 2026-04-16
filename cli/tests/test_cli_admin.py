import json

import typer
from typer.testing import CliRunner

import secure_message_cli as cli


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self):
        return self._payload


def _patch_state(monkeypatch, tmp_path, username: str = "alice", role: str = "user"):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(cli, "HISTORY_FILE", tmp_path / "history.jsonl")
    state = {
        "backend_url": "http://localhost:8080",
        "auth": {
            "token": "test-token",
            "username": username,
            "role": role,
        },
        "keys": {
            "public_key": "public",
            "encrypted_private_key": "encrypted",
        },
        "save_history": True,
    }
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")


def test_send_is_blocked_for_dedicated_admin(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path, username="ADMIN", role="admin")
    runner = CliRunner()

    def fake_request(method: str, url: str, token=None, **kwargs):
        raise AssertionError(f"Unexpected request: {method} {url}")

    monkeypatch.setattr(cli, "_request", fake_request)

    result = runner.invoke(cli.app, ["send", "bob", "hello"])

    assert result.exit_code == 1
    assert "Admin sessions are limited to user management." in result.stdout


def test_shell_for_dedicated_admin_only_shows_directory_actions(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path, username="ADMIN", role="admin")
    runner = CliRunner()
    capture: dict[str, object] = {}

    def fake_print_menu(title: str, options: list[tuple[str, str]], info_lines=None, footer_lines=None) -> None:
        capture["title"] = title
        capture["options"] = options
        capture["footer_lines"] = footer_lines

    def fake_prompt_choice(prompt: str, valid: set[str], default=None) -> str:
        raise typer.Exit()

    def fail_unlock(state: dict):
        raise AssertionError("ADMIN shell should not unlock the inbox.")

    monkeypatch.setattr(cli, "_print_menu", fake_print_menu)
    monkeypatch.setattr(cli, "_prompt_choice", fake_prompt_choice)
    monkeypatch.setattr(cli, "_unlock_private_key_once", fail_unlock)

    result = runner.invoke(cli.app, ["shell"])

    assert result.exit_code == 0
    assert capture["title"] == "Secure Message Session"
    assert capture["options"] == [("1", "List users"), ("2", "Delete user"), ("3", "Exit")]
    assert capture["footer_lines"] == ["Press 1-3"]


def test_admin_users_lists_registered_usernames(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path, username="ADMIN", role="admin")
    runner = CliRunner()

    def fake_request(method: str, url: str, token=None, **kwargs):
        assert token == "test-token"
        if method == "GET" and url.endswith("/api/me"):
            return _FakeResponse(
                200,
                {
                    "username": "ADMIN",
                    "role": "admin",
                    "public_key": "public",
                    "encrypted_private_key": "encrypted",
                },
            )
        if method == "GET" and url.endswith("/api/admin/users"):
            return _FakeResponse(200, {"users": [{"username": "ADMIN"}, {"username": "alice"}]})
        raise AssertionError(f"Unexpected request: {method} {url}")

    monkeypatch.setattr(cli, "_request", fake_request)

    result = runner.invoke(cli.app, ["admin", "users"])

    assert result.exit_code == 0
    assert "Username" in result.stdout
    assert "ADMIN" in result.stdout
    assert "alice" in result.stdout


def test_admin_delete_user_calls_backend_and_reports_success(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path, username="ADMIN", role="admin")
    runner = CliRunner()

    def fake_request(method: str, url: str, token=None, **kwargs):
        assert token == "test-token"
        if method == "GET" and url.endswith("/api/me"):
            return _FakeResponse(
                200,
                {
                    "username": "ADMIN",
                    "role": "admin",
                    "public_key": "public",
                    "encrypted_private_key": "encrypted",
                },
            )
        if method == "DELETE" and url.endswith("/api/admin/users/alice"):
            return _FakeResponse(200, {"status": "deleted"})
        raise AssertionError(f"Unexpected request: {method} {url}")

    monkeypatch.setattr(cli, "_request", fake_request)

    result = runner.invoke(cli.app, ["admin", "delete-user", "alice", "--force"])

    assert result.exit_code == 0
    assert "Deleted user alice." in result.stdout


def test_admin_delete_user_is_blocked_for_non_admin(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path, username="alice", role="user")
    runner = CliRunner()

    def fake_request(method: str, url: str, token=None, **kwargs):
        assert token == "test-token"
        if method == "GET" and url.endswith("/api/me"):
            return _FakeResponse(
                200,
                {
                    "username": "alice",
                    "role": "user",
                    "public_key": "public",
                    "encrypted_private_key": "encrypted",
                },
            )
        raise AssertionError(f"Unexpected request: {method} {url}")

    monkeypatch.setattr(cli, "_request", fake_request)

    result = runner.invoke(cli.app, ["admin", "delete-user", "bob", "--force"])

    assert result.exit_code == 1
    assert "Admin access required." in result.stdout
