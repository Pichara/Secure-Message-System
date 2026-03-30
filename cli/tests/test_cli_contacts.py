import json

from typer.testing import CliRunner

import secure_message_cli as cli


def _patch_state(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(cli, "HISTORY_FILE", tmp_path / "history.jsonl")


def test_contacts_add_list_remove(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["contacts", "add", "bob", "bob_user"])
    assert result.exit_code == 0

    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["contacts"]["bob"] == "bob_user"

    result = runner.invoke(cli.app, ["contacts", "list"])
    assert result.exit_code == 0
    assert "bob" in result.stdout
    assert "bob_user" in result.stdout

    result = runner.invoke(cli.app, ["contacts", "remove", "bob"])
    assert result.exit_code == 0

    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert "bob" not in state.get("contacts", {})
