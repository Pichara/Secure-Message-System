import json

from typer.testing import CliRunner

import secure_message_cli as cli


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or (json.dumps(payload) if payload is not None else "")

    def json(self):
        return self._payload


def _patch_state(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(cli, "HISTORY_FILE", tmp_path / "history.jsonl")
    state = {
        "backend_url": "http://localhost:8080",
        "auth": {"token": "test-token", "username": "alice"},
        "keys": {},
        "save_history": True,
    }
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")


def test_contacts_add_list_remove(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path)
    runner = CliRunner()
    contacts: list[dict[str, str]] = []

    def fake_request(method: str, url: str, token=None, **kwargs):
        assert token == "test-token"
        if method == "POST" and url.endswith("/api/contacts"):
            payload = kwargs["json"]
            contacts[:] = [item for item in contacts if item["alias"] != payload["alias"]]
            contacts.append({"alias": payload["alias"], "username": payload["username"]})
            return _FakeResponse(201, {"status": "saved"})
        if method == "GET" and url.endswith("/api/contacts"):
            return _FakeResponse(200, sorted(contacts, key=lambda item: item["alias"]))
        if method == "DELETE" and "/api/contacts/" in url:
            alias = url.rsplit("/", 1)[-1]
            before = len(contacts)
            contacts[:] = [item for item in contacts if item["alias"] != alias]
            if len(contacts) == before:
                return _FakeResponse(404, {"error": "alias_not_found"})
            return _FakeResponse(200, {"status": "removed"})
        raise AssertionError(f"Unexpected request: {method} {url}")

    monkeypatch.setattr(cli, "_request", fake_request)

    result = runner.invoke(cli.app, ["contacts", "add", "bob", "bob_user"])
    assert result.exit_code == 0
    assert contacts == [{"alias": "bob", "username": "bob_user"}]

    result = runner.invoke(cli.app, ["contacts", "list"])
    assert result.exit_code == 0
    assert "bob" in result.stdout
    assert "bob_user" in result.stdout

    result = runner.invoke(cli.app, ["contacts", "remove", "bob"])
    assert result.exit_code == 0
    assert contacts == []

    saved_state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert "contacts" not in saved_state
