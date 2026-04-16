import base64
import json

from typer.testing import CliRunner

import secure_message_cli as cli


def _patch_state(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(cli, "HISTORY_FILE", tmp_path / "history.jsonl")
    state = {
        "backend_url": "http://localhost:8080",
        "auth": {"token": "test-token", "username": "alice", "role": "user"},
        "keys": {},
        "save_history": True,
    }
    (tmp_path / "state.json").write_text(json.dumps(state), encoding="utf-8")


def test_attachments_save_treats_suffixless_path_as_directory(tmp_path, monkeypatch):
    _patch_state(monkeypatch, tmp_path)
    runner = CliRunner()

    content = {
        "kind": "attachment",
        "display": "[attachment] proof.bin (application/octet-stream, 7 bytes)",
        "name": "proof.bin",
        "mime": "application/octet-stream",
        "size_bytes": 7,
        "caption": "",
        "bytes_b64": base64.urlsafe_b64encode(b"payload").decode("ascii"),
    }

    monkeypatch.setattr(cli, "_message_content_for_id", lambda state, auth, message_id: (content, "local history"))

    output_dir = tmp_path / "downloads"
    result = runner.invoke(cli.app, ["attachments", "save", "42", str(output_dir)])

    assert result.exit_code == 0
    saved_file = output_dir / "proof.bin"
    assert saved_file.exists()
    assert saved_file.read_bytes() == b"payload"
    assert "Saved attachment from local history" in result.stdout


def test_write_attachment_file_uses_unique_name_when_target_exists(tmp_path):
    original = tmp_path / "proof.bin"
    original.write_bytes(b"existing")

    saved_file = cli._write_attachment_file(tmp_path, "proof.bin", b"payload")

    assert saved_file == tmp_path / "proof (1).bin"
    assert saved_file.read_bytes() == b"payload"
    assert original.read_bytes() == b"existing"
