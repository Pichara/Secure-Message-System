import base64
import copy
import inspect
import json
import mimetypes
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
import typer
import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization

app = typer.Typer(add_completion=False, no_args_is_help=False)
config_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")
contacts_app = typer.Typer(no_args_is_help=True)
app.add_typer(contacts_app, name="contacts")
admin_app = typer.Typer(no_args_is_help=True)
app.add_typer(admin_app, name="admin")
attachments_app = typer.Typer(no_args_is_help=True)
app.add_typer(attachments_app, name="attachments")

console = Console(force_terminal=False)

STATE_DIR = Path.home() / ".secure-message-cli"
STATE_FILE = STATE_DIR / "state.json"
HISTORY_FILE = STATE_DIR / "history.jsonl"

DEFAULT_BACKEND_URL = "http://localhost:8080"
PBKDF2_ITERATIONS = 200_000
MAX_ATTACHMENT_BYTES = 128 * 1024
PASSWORD_POLICY_MESSAGE = (
    "Password must be 8-128 characters and include at least one number "
    "and one special character."
)

# Typer 0.12.x calls Click's make_metavar() without ctx, but Click 8.3+ requires ctx.
# This patch keeps help output working across Click versions.
if "ctx" in inspect.signature(click.Parameter.make_metavar).parameters:
    _orig_make_metavar = click.Parameter.make_metavar

    def _compat_make_metavar(self, ctx=None):  # type: ignore[override]
        if ctx is None:
            ctx = click.get_current_context(silent=True)
            if ctx is None:
                ctx = click.Context(click.Command("secure-message"))
        return _orig_make_metavar(self, ctx)

    click.Parameter.make_metavar = _compat_make_metavar  # type: ignore[assignment]


# Encode bytes as URL-safe base64 (ASCII string).
def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


# Decode URL-safe base64 strings back to bytes.
def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


# Load persisted CLI state (or defaults if missing).
def _state() -> dict:
    if not STATE_FILE.exists():
        return {
            "backend_url": DEFAULT_BACKEND_URL,
            "auth": {},
            "keys": {},
            "save_history": True,
        }
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    if "contacts" in state:
        state.pop("contacts", None)
        STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    return state


# Persist state to disk with best-effort permissions.
def _save_state(state: dict) -> None:
    state.pop("contacts", None)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    if os.name != "nt":
        STATE_FILE.chmod(0o600)


# Resolve backend URL with fallback to default.
def _backend_url(state: dict) -> str:
    return state.get("backend_url") or DEFAULT_BACKEND_URL


def _resolve_alias(state: dict, name: str) -> str:
    auth = state.get("auth") or {}
    if not _auth_valid(auth):
        return name
    try:
        contacts = _contact_map(state, auth)
    except Exception:
        return name
    return contacts.get(name, name)


# Mask secrets for display-only output.
def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


# Return a copy of state with secrets redacted.
def _masked_state(state: dict) -> dict:
    masked = copy.deepcopy(state)
    auth = masked.get("auth") or {}
    if auth.get("token"):
        auth["token"] = _mask_secret(auth["token"])
    masked["auth"] = auth
    keys = masked.get("keys") or {}
    if keys.get("encrypted_private_key"):
        keys["encrypted_private_key"] = _mask_secret(keys["encrypted_private_key"])
    masked["keys"] = keys
    return masked


def _password_policy_error(password: str) -> Optional[str]:
    if len(password) < 8 or len(password) > 128:
        return PASSWORD_POLICY_MESSAGE
    if not any(char.isdigit() for char in password):
        return PASSWORD_POLICY_MESSAGE
    if not any((not char.isalnum()) and (not char.isspace()) for char in password):
        return PASSWORD_POLICY_MESSAGE
    return None


# Ensure an auth token is present for protected actions.
def _require_auth(state: dict) -> dict:
    auth = state.get("auth") or {}
    token = auth.get("token")
    username = auth.get("username")
    if not token or not username:
        typer.secho("Not logged in. Run: login <username>", fg=typer.colors.RED)
        raise typer.Exit(1)
    return auth


# Parse stored expiry timestamps, defaulting to UTC.
def _parse_expires_at(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


# Validate cached auth data and TTL.
def _auth_valid(auth: dict) -> bool:
    token = auth.get("token")
    username = auth.get("username")
    expires_at = _parse_expires_at(auth.get("expires_at"))
    if not token or not username:
        return False
    if expires_at and datetime.now(timezone.utc) >= expires_at:
        return False
    return True


def _auth_role(auth: dict) -> str:
    role = str(auth.get("role") or "user").strip().lower()
    return role or "user"


# Derive a symmetric key from password + salt using PBKDF2.
def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# Encrypt private key bytes locally (AES-GCM; salt+nonce stored in payload).
def _encrypt_private_key(private_bytes: bytes, password: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, private_bytes, None)
    payload = {
        "ciphertext": _b64encode(ciphertext),
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
    }
    return json.dumps(payload)


# Decrypt locally stored private key payload.
def _decrypt_private_key(encrypted_payload: str, password: str) -> bytes:
    data = json.loads(encrypted_payload)
    salt = _b64decode(data["salt"])
    nonce = _b64decode(data["nonce"])
    ciphertext = _b64decode(data["ciphertext"])
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


# Generate an X25519 keypair for E2EE.
def _generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


# Serialize public key to URL-safe base64.
def _serialize_public_key(public_key: x25519.X25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(raw)


# Serialize private key to raw bytes (never stored unencrypted on disk).
def _serialize_private_key(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


# Load + decrypt the private key from state using a user password.
def _load_private_key_from_state(state: dict, password: str) -> x25519.X25519PrivateKey:
    encrypted_payload = state.get("keys", {}).get("encrypted_private_key")
    if not encrypted_payload:
        typer.secho("No local private key found. Login to fetch it.", fg=typer.colors.RED)
        raise typer.Exit(1)
    private_bytes = _decrypt_private_key(encrypted_payload, password)
    return x25519.X25519PrivateKey.from_private_bytes(private_bytes)


# Encrypt a message using X25519 ECDH + HKDF + AES-GCM.
def _encrypt_message(plaintext: str, recipient_public_b64: str) -> tuple[str, str, str]:
    recipient_public = x25519.X25519PublicKey.from_public_bytes(_b64decode(recipient_public_b64))
    eph_private = x25519.X25519PrivateKey.generate()
    eph_public = eph_private.public_key()

    # Derive a fresh symmetric key per message using an ephemeral ECDH exchange.
    shared = eph_private.exchange(recipient_public)
    salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"secure-message-ecdh",
    )
    key = hkdf.derive(shared)

    iv = os.urandom(12)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(iv, plaintext.encode("utf-8"), None)

    # Payload contains ephemeral public key + salt (needed to derive the same AES key).
    encrypted_key = json.dumps({
        "epk": _b64encode(
            eph_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        ),
        "salt": _b64encode(salt),
    })

    return encrypted_key, _b64encode(ciphertext), _b64encode(iv)


# Decrypt a message given the encrypted key payload and recipient private key.
def _decrypt_message(ciphertext_b64: str, iv_b64: str, encrypted_key_payload: str, private_key: x25519.X25519PrivateKey) -> str:
    data = json.loads(encrypted_key_payload)
    eph_public = x25519.X25519PublicKey.from_public_bytes(_b64decode(data["epk"]))
    salt = _b64decode(data["salt"])

    # Recreate the same derived key from the sender's ephemeral public key.
    shared = private_key.exchange(eph_public)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"secure-message-ecdh",
    )
    key = hkdf.derive(shared)
    aes = AESGCM(key)
    plaintext = aes.decrypt(_b64decode(iv_b64), _b64decode(ciphertext_b64), None)
    return plaintext.decode("utf-8")


def _safe_filename(name: str, fallback: str = "attachment.bin") -> str:
    candidate = Path(name or fallback).name.strip()
    if not candidate:
        return fallback
    cleaned = "".join(char for char in candidate if char.isalnum() or char in {"-", "_", ".", " "}).strip()
    return cleaned or fallback


def _detect_image_type(data: bytes) -> Optional[tuple[str, str]]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", ".gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp", ".webp"
    return None


def _build_image_envelope(file_path: Path, caption: Optional[str]) -> tuple[str, dict[str, Any]]:
    raw_bytes = file_path.read_bytes()
    if not raw_bytes:
        raise ValueError("Image file is empty.")
    if len(raw_bytes) > MAX_ATTACHMENT_BYTES:
        raise ValueError(f"Image exceeds {MAX_ATTACHMENT_BYTES} bytes.")

    detected = _detect_image_type(raw_bytes)
    if detected is None:
        raise ValueError("Unsupported image type. Use PNG, JPEG, GIF, or WebP.")
    mime, fallback_suffix = detected

    file_name = _safe_filename(file_path.name or f"image{fallback_suffix}", fallback=f"image{fallback_suffix}")
    if not Path(file_name).suffix:
        guessed_ext = mimetypes.guess_extension(mime) or fallback_suffix
        file_name = f"{file_name}{guessed_ext}"

    envelope = {
        "kind": "image",
        "caption": (caption or "").strip(),
        "attachment": {
            "name": file_name,
            "mime": mime,
            "size_bytes": len(raw_bytes),
            "bytes_b64": _b64encode(raw_bytes),
        },
    }
    metadata = {
        "name": file_name,
        "mime": mime,
        "size_bytes": len(raw_bytes),
        "caption": envelope["caption"],
    }
    return json.dumps(envelope), metadata


def _message_content(raw_content: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError:
        return {"kind": "text", "raw": raw_content, "display": raw_content}

    if not isinstance(payload, dict) or payload.get("kind") != "image":
        return {"kind": "text", "raw": raw_content, "display": raw_content}

    attachment = payload.get("attachment")
    if not isinstance(attachment, dict):
        return {"kind": "text", "raw": raw_content, "display": raw_content}

    name = _safe_filename(str(attachment.get("name") or "image.bin"))
    mime = str(attachment.get("mime") or "application/octet-stream")
    size_bytes = attachment.get("size_bytes")
    caption = str(payload.get("caption") or "").strip()
    bytes_b64 = attachment.get("bytes_b64")

    if not isinstance(size_bytes, int):
        try:
            size_bytes = len(_b64decode(str(bytes_b64)))
        except Exception:
            size_bytes = 0

    display = f"[image] {name} ({mime}, {size_bytes} bytes)"
    if caption:
        display = f"{display} caption={caption}"

    return {
        "kind": "image",
        "raw": raw_content,
        "display": display,
        "name": name,
        "mime": mime,
        "size_bytes": size_bytes,
        "caption": caption,
        "bytes_b64": bytes_b64,
    }


def _history_entry_from_record(entry: dict) -> Optional[dict[str, Any]]:
    if "id" not in entry:
        return None
    raw_content = entry.get("content")
    if raw_content is None and "plaintext" in entry:
        raw_content = entry["plaintext"]
    if raw_content is None:
        return None
    parsed = _message_content(str(raw_content))
    parsed["raw"] = str(raw_content)
    return parsed


def _history_display(history: dict, message_id: Any) -> str:
    entry = history.get(str(message_id))
    if not entry:
        return "[sent message not stored locally]"
    return str(entry.get("display") or "[sent message not stored locally]")


def _refresh_me_profile(state: dict, auth: dict) -> dict:
    me_url = f"{_backend_url(state)}/api/me"
    me_resp = _request("GET", me_url, token=auth["token"])
    if me_resp.status_code != 200:
        typer.secho(f"Failed to fetch /api/me: {me_resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    me = me_resp.json()
    auth["username"] = me.get("username") or auth.get("username")
    auth["role"] = str(me.get("role") or auth.get("role") or "user")
    state["auth"] = auth
    keys = state.get("keys") or {}
    if me.get("public_key"):
        keys["public_key"] = me["public_key"]
    if me.get("encrypted_private_key"):
        keys["encrypted_private_key"] = me["encrypted_private_key"]
    state["keys"] = keys
    _save_state(state)
    return me


def _fetch_contacts(state: dict, auth: dict) -> list[dict[str, str]]:
    resp = _request("GET", f"{_backend_url(state)}/api/contacts", token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Failed to fetch contacts: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)
    payload = resp.json()
    contacts: list[dict[str, str]] = []
    if isinstance(payload, list):
        for item in payload:
            if not isinstance(item, dict):
                continue
            alias = str(item.get("alias") or "").strip()
            username = str(item.get("username") or "").strip()
            if alias and username:
                contacts.append({"alias": alias, "username": username})
    return contacts


def _contact_map(state: dict, auth: dict) -> dict[str, str]:
    return {item["alias"]: item["username"] for item in _fetch_contacts(state, auth)}


def _resolve_admin_usernames(payload: Any) -> list[str]:
    users = payload.get("users") if isinstance(payload, dict) else payload
    if not isinstance(users, list):
        return []
    usernames: list[str] = []
    for item in users:
        if isinstance(item, str):
            username = item
        elif isinstance(item, dict):
            username = item.get("username")
        else:
            username = None
        if username:
            usernames.append(str(username))
    return usernames


def _message_content_for_id(
    state: dict,
    auth: dict,
    message_id: int,
    password: Optional[str] = None,
) -> tuple[dict[str, Any], str]:
    history = _load_history()
    history_entry = history.get(str(message_id))
    if history_entry:
        return history_entry, "local history"

    url = f"{_backend_url(state)}/api/messages"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Failed to fetch messages: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    target = next((msg for msg in resp.json() if int(msg.get("id", -1)) == message_id), None)
    if target is None:
        typer.secho("Message not found.", fg=typer.colors.RED)
        raise typer.Exit(1)

    if target.get("recipient") != auth.get("username"):
        typer.secho(
            "Only received attachments can be decrypted from the server. "
            "Use local history for sent attachments.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(1)

    if not password:
        password = typer.prompt("Password", hide_input=True)
    try:
        private_key = _load_private_key_from_state(state, password)
    except Exception:
        typer.secho("Failed to decrypt private key.", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        plaintext = _decrypt_message(
            target.get("ciphertext", ""),
            target.get("iv", ""),
            target.get("encrypted_key", ""),
            private_key,
        )
    except Exception:
        typer.secho("Failed to decrypt message.", fg=typer.colors.RED)
        raise typer.Exit(1)

    return _message_content(plaintext), "server"


def _write_attachment_file(output_path: Path, name: str, raw_bytes: bytes) -> Path:
    target = output_path
    if output_path.exists() and output_path.is_dir():
        target = output_path / name
    elif output_path.suffix == "" and str(output_path).endswith((os.sep, "/")):
        target = output_path / name

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw_bytes)
    if os.name != "nt":
        target.chmod(0o600)
    return target


# Wrapper for backend HTTP requests with consistent headers/timeouts.
def _request(method: str, url: str, token: Optional[str] = None, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.request(method, url, headers=headers, timeout=15, **kwargs)


# Prompt for a single-character choice using prompt_toolkit if available.
def _prompt_choice(prompt: str, valid: set[str], default: Optional[str] = None) -> str:
    try:
        return _prompt_choice_ptk(prompt, valid, default)
    except Exception:
        return _prompt_choice_typer(prompt, valid, default)


# Fallback prompt using Typer for choice inputs.
def _prompt_choice_typer(prompt: str, valid: set[str], default: Optional[str]) -> str:
    while True:
        choice = typer.prompt(prompt, default=default) if default is not None else typer.prompt(prompt)
        choice = choice.strip()
        if choice in valid:
            return choice
        typer.secho(f"Invalid choice: {choice}", fg=typer.colors.RED)


# Fast single-key choice prompt using prompt_toolkit key bindings.
def _prompt_choice_ptk(prompt: str, valid: set[str], default: Optional[str]) -> str:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.key_binding import KeyBindings

    session = PromptSession()
    kb = KeyBindings()
    valid_set = set(valid)

    @kb.add("c-c")
    def _exit(event):
        event.app.exit(result="__INT__")

    @kb.add("enter")
    def _enter(event):
        if default is not None and default in valid_set:
            event.app.exit(result=default)
        else:
            event.app.exit(result="")

    @kb.add_any()
    def _any_key(event):
        data = event.data
        if not data:
            return
        if data in valid_set:
            event.app.exit(result=data)
            return
        event.app.bell()

    while True:
        result = session.prompt(f"{prompt} ", key_bindings=kb)
        if result == "__INT__":
            raise typer.Exit(1)
        result = result.strip()
        if result in valid_set:
            return result
        if result == "" and default is not None and default in valid_set:
            return default
        typer.secho(f"Invalid choice: {result}", fg=typer.colors.RED)


# Launch a new shell window for an authenticated session when supported.
def _launch_shell_window(script_path: Path) -> bool:
    cmd = [sys.executable, str(script_path), "shell"]
    if os.name == "nt":
        try:
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
            return True
        except Exception:
            return False
    return False


# Render an info panel (optional).
def _render_status(title: str, lines: list[str]) -> None:
    if not lines:
        return
    body = "\n".join(lines)
    console.print(Panel(body, title=title, box=box.SIMPLE, expand=False))


# Render a simple Rich table.
def _render_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, box=box.SIMPLE, show_lines=False)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.print(table)


# Render a basic menu with optional status/footer lines.
def _print_menu(
    title: str,
    options: list[tuple[str, str]],
    info_lines: Optional[list[str]] = None,
    footer_lines: Optional[list[str]] = None,
) -> None:
    _render_status("Status", info_lines or [])
    table = Table(title=title, box=box.SIMPLE, show_header=False)
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Action")
    for key, label in options:
        table.add_row(key, label)
    console.print(table)
    if footer_lines:
        console.print("\n".join(footer_lines))


# Fetch all messages visible to the current user.
def _fetch_messages(state: dict, auth: dict) -> list[dict]:
    url = f"{_backend_url(state)}/api/messages"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Failed to fetch messages: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)
    return resp.json()


# Print a summary table of messages received by the user.
def _list_received_messages(messages: list[dict], username: str) -> None:
    received = [msg for msg in messages if msg.get("recipient") == username]
    if not received:
        console.print("No received messages.")
        return
    rows = []
    for idx, msg in enumerate(received, start=1):
        created_at = msg.get("created_at", "unknown")
        sender = msg.get("sender", "unknown")
        msg_id = str(msg.get("id", "?"))
        rows.append([str(idx), created_at, sender, msg_id])
    _render_table("Received Messages", ["#", "Time", "From", "Id"], rows)


# Build a list of conversations sorted by most recent timestamp.
def _conversation_list(messages: list[dict], username: str) -> list[tuple[str, str]]:
    latest_by_user: dict[str, str] = {}
    for msg in messages:
        sender = msg.get("sender")
        recipient = msg.get("recipient")
        if not sender or not recipient:
            continue
        other = recipient if sender == username else sender if recipient == username else None
        if other is None:
            continue
        created_at = msg.get("created_at", "")
        current = latest_by_user.get(other)
        if current is None or created_at > current:
            latest_by_user[other] = created_at
    conversations = [(user, latest_by_user[user]) for user in latest_by_user]
    conversations.sort(key=lambda item: item[1], reverse=True)
    return conversations


# Prompt user to select a conversation from the list.
def _select_conversation(conversations: list[tuple[str, str]]) -> Optional[str]:
    if not conversations:
        console.print("No conversations.")
        return None
    rows = []
    for idx, (user, latest) in enumerate(conversations, start=1):
        rows.append([str(idx), user, latest or "-"])
    _render_table("Conversations", ["#", "User", "Last Message"], rows)
    while True:
        choice = typer.prompt("Open conversation (0 to back)").strip()
        if choice == "0":
            return None
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(conversations):
                return conversations[index - 1][0]
        typer.secho("Invalid selection.", fg=typer.colors.RED)


# Display a conversation (decrypting inbound messages when possible).
def _display_conversation(
    messages: list[dict],
    username: str,
    with_user: str,
    private_key: Optional[x25519.X25519PrivateKey],
) -> None:
    history = _load_history()
    convo = [
        msg
        for msg in messages
        if (msg.get("sender") == username and msg.get("recipient") == with_user)
        or (msg.get("sender") == with_user and msg.get("recipient") == username)
    ]
    if not convo:
        console.print("No messages in this conversation.")
        return

    convo.sort(key=lambda msg: msg.get("created_at", ""))
    rows = _conversation_rows(convo, username, private_key, history)
    _render_table(f"Conversation with {with_user}", ["Id", "Time", "From", "To", "Message"], rows)


# Produce table rows for a conversation, showing decrypted text when available.
def _conversation_rows(
    convo: list[dict],
    username: str,
    private_key: Optional[x25519.X25519PrivateKey],
    history: dict,
) -> list[list[str]]:
    rows = []
    for msg in convo:
        msg_id = str(msg.get("id", "?"))
        sender = msg.get("sender", "unknown")
        recipient = msg.get("recipient", "unknown")
        created_at = msg.get("created_at", "unknown")
        if recipient == username:
            if private_key is None:
                # Inbox remains locked until the user unlocks the private key locally.
                plaintext = "[inbox locked]"
            else:
                try:
                    plaintext = _decrypt_message(
                        msg.get("ciphertext", ""),
                        msg.get("iv", ""),
                        msg.get("encrypted_key", ""),
                        private_key,
                    )
                    plaintext = _message_content(plaintext)["display"]
                except Exception:
                    plaintext = "[decryption failed]"
        else:
            # Sent-message plaintext is stored locally only (server never sees it).
            plaintext = _history_display(history, msg.get("id"))
        rows.append([msg_id, created_at, sender, recipient, plaintext])
    return rows


# Prompt once to unlock the private key (optional for reading inbox).
def _unlock_private_key_once(state: dict) -> Optional[x25519.X25519PrivateKey]:
    if not state.get("keys", {}).get("encrypted_private_key"):
        typer.secho("No local private key found. Login to fetch it.", fg=typer.colors.RED)
        return None
    password = typer.prompt(
        "Password (for inbox decryption, leave blank to skip)",
        hide_input=True,
        default="",
        show_default=False,
    )
    if not password:
        return None
    try:
        return _load_private_key_from_state(state, password)
    except Exception:
        typer.secho("Failed to decrypt private key.", fg=typer.colors.RED)
        return None


# Set backend URL for subsequent API calls.
@config_app.command("set-url")
def config_set_url(url: str):
    state = _state()
    state["backend_url"] = url.rstrip("/")
    _save_state(state)
    typer.echo(f"Backend URL set to {state['backend_url']}")


# Show current configuration (masked by default).
@config_app.command("show")
def config_show(full: bool = typer.Option(False, "--full")):
    state = _state()
    if not full:
        state = _masked_state(state)
    typer.echo(json.dumps(state, indent=2))


# Toggle local plaintext history storage.
@config_app.command("set-history")
def config_set_history(value: str):
    normalized = value.strip().lower()
    if normalized in {"on", "true", "1", "yes"}:
        enabled = True
    elif normalized in {"off", "false", "0", "no"}:
        enabled = False
    else:
        typer.secho("Value must be on/off or true/false.", fg=typer.colors.RED)
        raise typer.Exit(1)
    state = _state()
    state["save_history"] = enabled
    _save_state(state)
    status = "on" if enabled else "off"
    typer.echo(f"History saving set to {status}.")


@admin_app.command("users")
def admin_users():
    state = _state()
    auth = _require_auth(state)
    _refresh_me_profile(state, auth)
    auth = state["auth"]
    if _auth_role(auth) != "admin":
        typer.secho("Admin access required.", fg=typer.colors.RED)
        raise typer.Exit(1)

    url = f"{_backend_url(state)}/api/admin/users"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Admin user list failed: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    usernames = _resolve_admin_usernames(resp.json())
    if not usernames:
        console.print("No users found.")
        return
    rows = [[name] for name in sorted(usernames)]
    _render_table("Registered Users", ["Username"], rows)


@attachments_app.command("show")
def attachments_show(message_id: int):
    state = _state()
    auth = _require_auth(state)
    content, source = _message_content_for_id(state, auth, message_id)
    if content.get("kind") != "image":
        typer.secho("Message is not an image attachment.", fg=typer.colors.RED)
        raise typer.Exit(1)

    rows = [
        ["Message Id", str(message_id)],
        ["Source", source],
        ["Name", str(content.get("name") or "")],
        ["Mime", str(content.get("mime") or "")],
        ["Size", f"{content.get('size_bytes', 0)} bytes"],
        ["Caption", str(content.get("caption") or "-")],
    ]
    _render_table("Attachment Details", ["Field", "Value"], rows)


@attachments_app.command("save")
def attachments_save(message_id: int, output_path: Path):
    state = _state()
    auth = _require_auth(state)
    content, source = _message_content_for_id(state, auth, message_id)
    if content.get("kind") != "image":
        typer.secho("Message is not an image attachment.", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        raw_bytes = _b64decode(str(content.get("bytes_b64") or ""))
    except Exception:
        typer.secho("Attachment payload is invalid.", fg=typer.colors.RED)
        raise typer.Exit(1)

    saved_path = _write_attachment_file(output_path, str(content.get("name") or "attachment.bin"), raw_bytes)
    typer.echo(f"Saved attachment from {source} to {saved_path}")


# Add or update a contact alias.
@contacts_app.command("add")
def contacts_add(alias: str, username: str):
    state = _state()
    auth = _require_auth(state)
    payload = {"alias": alias.strip(), "username": username.strip()}
    resp = _request("POST", f"{_backend_url(state)}/api/contacts", token=auth["token"], json=payload)
    if resp.status_code != 201:
        typer.secho(f"Failed to save contact: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)
    console.print(f"Saved contact {payload['alias']} -> {payload['username']}")


# List saved contact aliases.
@contacts_app.command("list")
def contacts_list():
    state = _state()
    auth = _require_auth(state)
    contacts = _fetch_contacts(state, auth)
    if not contacts:
        console.print("No contacts saved.")
        return
    rows = [[item["alias"], item["username"]] for item in contacts]
    _render_table("Contacts", ["Alias", "Username"], rows)


# Remove a saved contact alias.
@contacts_app.command("remove")
def contacts_remove(alias: str):
    state = _state()
    auth = _require_auth(state)
    resp = _request(
        "DELETE",
        f"{_backend_url(state)}/api/contacts/{alias.strip()}",
        token=auth["token"],
    )
    if resp.status_code == 404:
        typer.secho("Alias not found.", fg=typer.colors.RED)
        raise typer.Exit(1)
    if resp.status_code != 200:
        typer.secho(f"Failed to remove contact: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)
    console.print(f"Removed contact {alias}.")


# Call a Typer command and swallow Exit to keep the menu loop alive.
def _safe_call(func, *args) -> bool:
    try:
        func(*args)
        return True
    except typer.Exit:
        return False


# Launch the Textual TUI if available.
def _run_tui() -> bool:
    try:
        from tui_app import run_tui
    except Exception as exc:
        typer.secho(f"TUI unavailable: {exc}", fg=typer.colors.YELLOW)
        return False
    run_tui()
    return True


# Default entrypoint: launch TUI if no subcommand provided.
@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        if not _run_tui():
            launcher()


# Explicitly run the TUI.
@app.command()
def tui():
    if not _run_tui():
        raise typer.Exit(1)


# Launcher with login/register flow and optional shell spawn.
@app.command()
def launcher():
    script_path = Path(__file__).resolve()
    while True:
        state = _state()
        auth = state.get("auth") or {}

        if _auth_valid(auth):
            if _launch_shell_window(script_path):
                typer.echo("Opened session in new terminal.")
                raise typer.Exit()
            typer.secho("Could not open new terminal. Using this window.", fg=typer.colors.YELLOW)
            shell()
            raise typer.Exit()

        typer.echo("")
        _print_menu(
            title="Secure Message Launcher",
            options=[("1", "Register"), ("2", "Login"), ("3", "Exit")],
            info_lines=[f"Backend: {_backend_url(state)}"],
            footer_lines=["Press 1-3"],
        )
        choice = _prompt_choice("secure@guest>", {"1", "2", "3"}, default="3")

        if choice == "1":
            username = typer.prompt("Username").strip()
            if username:
                _safe_call(register, username)
            continue
        if choice == "2":
            username = typer.prompt("Username").strip()
            if username:
                _safe_call(login, username)
            continue
        raise typer.Exit()


# Register a new user and upload public + encrypted private key.
@app.command()
def register(username: str):
    state = _state()
    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    password_error = _password_policy_error(password)
    if password_error:
        typer.secho(f"Register failed: {password_error}", fg=typer.colors.RED)
        raise typer.Exit(1)

    private_key, public_key = _generate_keypair()
    public_key_b64 = _serialize_public_key(public_key)
    encrypted_private_key = _encrypt_private_key(_serialize_private_key(private_key), password)

    payload = {
        "username": username,
        "password": password,
        "public_key": public_key_b64,
        "encrypted_private_key": encrypted_private_key,
    }

    url = f"{_backend_url(state)}/api/register"
    resp = _request("POST", url, json=payload)
    if resp.status_code != 201:
        message = resp.text
        try:
            payload = resp.json()
            if payload.get("error") == "invalid_password":
                message = payload.get("message") or PASSWORD_POLICY_MESSAGE
            elif payload.get("error") == "registration_failed":
                message = "Registration failed."
            else:
                message = resp.text
        except Exception:
            pass
        typer.secho(f"Register failed: {message}", fg=typer.colors.RED)
        raise typer.Exit(1)

    state["keys"] = {
        "public_key": public_key_b64,
        "encrypted_private_key": encrypted_private_key,
    }
    _save_state(state)
    typer.echo("Registered. Run 'login <username>' to get a token.")


# Login and persist auth + server-side key blobs.
@app.command()
def login(username: str):
    state = _state()
    password = typer.prompt("Password", hide_input=True)

    url = f"{_backend_url(state)}/api/login"
    resp = _request("POST", url, json={"username": username, "password": password})
    if resp.status_code != 200:
        typer.secho(f"Login failed: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    data = resp.json()
    token = data["token"]
    expires_in = int(data.get("expires_in", 3600))
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    state["auth"] = {
        "token": token,
        "username": username,
        "role": "user",
        "expires_at": expires_at.isoformat(),
    }
    _refresh_me_profile(state, state["auth"])

    # Validate the supplied password can decrypt the stored private key blob.
    try:
        _decrypt_private_key(state["keys"]["encrypted_private_key"], password)
    except Exception:
        typer.secho("Warning: password could not decrypt private key.", fg=typer.colors.YELLOW)

    typer.echo("Login ok.")


# Interactive shell menu for messaging actions.
@app.command()
def shell():
    state = _state()
    auth = state.get("auth") or {}
    if not _auth_valid(auth):
        typer.secho("Not logged in. Run the launcher to login.", fg=typer.colors.RED)
        raise typer.Exit(1)

    username = auth["username"]
    role = _auth_role(auth)
    private_key = _unlock_private_key_once(state)
    while True:
        typer.echo("")
        options = [("1", "Send message"), ("2", "View messages"), ("3", "Chat")]
        valid_choices = {"1", "2", "3"}
        footer = ["Press 1-4"]
        if role == "admin":
            options.append(("4", "List users"))
            options.append(("5", "Exit"))
            valid_choices.add("4")
            valid_choices.add("5")
            footer = ["Press 1-5"]
            default_choice = "5"
        else:
            options.append(("4", "Exit"))
            valid_choices.add("4")
            default_choice = "4"
        _print_menu(
            title="Secure Message Session",
            options=options,
            info_lines=[f"User: {username}", f"Role: {role}", f"Backend: {_backend_url(state)}"],
            footer_lines=footer,
        )
        choice = _prompt_choice(f"{username}@secure>", valid_choices, default=default_choice)

        if choice == "1":
            recipient = typer.prompt("Recipient").strip()
            if not recipient:
                typer.secho("Recipient required.", fg=typer.colors.RED)
                continue
            attachment_path = typer.prompt("Image path (leave blank for text)", default="", show_default=False).strip()
            if attachment_path:
                caption = typer.prompt("Caption (optional)", default="", show_default=False).strip()
                send(recipient, caption or None, file=Path(attachment_path))
                continue
            message = typer.prompt("Message").strip()
            if not message:
                typer.secho("Message required.", fg=typer.colors.RED)
                continue
            send(recipient, message)
            continue
        if choice == "2":
            messages = _fetch_messages(state, auth)
            _list_received_messages(messages, username)
            with_user = _select_conversation(_conversation_list(messages, username))
            if not with_user:
                continue
            _display_conversation(messages, username, with_user, private_key)
            continue
        if choice == "3":
            with_user = typer.prompt("Chat with").strip()
            if not with_user:
                typer.secho("User required.", fg=typer.colors.RED)
                continue
            with_user = _resolve_alias(state, with_user)
            _chat_flow(state, auth, with_user, private_key)
            continue
        if choice == "4" and role == "admin":
            admin_users()
            continue
        raise typer.Exit()


# Print the current username or "not logged in".
@app.command()
def whoami():
    state = _state()
    auth = state.get("auth") or {}
    if auth.get("username"):
        role = _auth_role(auth)
        if role == "admin":
            typer.echo(f"{auth['username']} (admin)")
        else:
            typer.echo(auth["username"])
    else:
        typer.echo("not logged in")


# Clear local auth state.
@app.command()
def logout():
    state = _state()
    state["auth"] = {}
    _save_state(state)
    typer.echo("Logged out.")


# Send an encrypted message to a recipient.
@app.command()
def send(
    recipient: str,
    message: Optional[str] = typer.Argument(None),
    no_history: bool = typer.Option(False, "--no-history"),
    file: Optional[Path] = typer.Option(None, "--file"),
    caption: Optional[str] = typer.Option(None, "--caption"),
):
    state = _state()
    auth = _require_auth(state)
    recipient = _resolve_alias(state, recipient)
    if file is None and not message:
        typer.secho("Provide a message or use --file for an image attachment.", fg=typer.colors.RED)
        raise typer.Exit(1)
    if file is not None and not file.exists():
        typer.secho("Attachment file not found.", fg=typer.colors.RED)
        raise typer.Exit(1)

    password = typer.prompt("Password", hide_input=True)
    try:
        _load_private_key_from_state(state, password)
    except Exception:
        typer.secho("Failed to decrypt private key.", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Fetch recipient public key for E2EE encryption.
    url = f"{_backend_url(state)}/api/users/{recipient}/public-key"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Failed to fetch public key: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    recipient_public_key = resp.json()["public_key"]
    content_to_encrypt = message or ""
    history_plaintext = message or ""
    if file is not None:
        attachment_caption = caption if caption is not None else (message or "")
        try:
            content_to_encrypt, attachment_meta = _build_image_envelope(file, attachment_caption)
        except OSError as exc:
            typer.secho(f"Failed to read image: {exc}", fg=typer.colors.RED)
            raise typer.Exit(1)
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED)
            raise typer.Exit(1)
        history_plaintext = _message_content(content_to_encrypt)["display"]
    elif caption:
        typer.secho("--caption can only be used with --file.", fg=typer.colors.RED)
        raise typer.Exit(1)

    encrypted_key, ciphertext, iv = _encrypt_message(content_to_encrypt, recipient_public_key)

    payload = {
        "recipient": recipient,
        "encrypted_key": encrypted_key,
        "ciphertext": ciphertext,
        "iv": iv,
    }
    post_url = f"{_backend_url(state)}/api/messages"
    post_resp = _request("POST", post_url, token=auth["token"], json=payload)
    if post_resp.status_code != 201:
        typer.secho(f"Send failed: {post_resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    msg_id = post_resp.json().get("id")
    # Store outbound plaintext locally (optional) for easier conversation view.
    save_history = state.get("save_history", True) and not no_history
    _append_history(
        {
            "id": msg_id,
            "sender": auth["username"],
            "recipient": recipient,
            "plaintext": history_plaintext,
            "content": content_to_encrypt,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
        save_history=save_history,
    )

    if file is not None:
        typer.echo(f"Image sent (id={msg_id}, file={attachment_meta['name']}).")
        return
    typer.echo(f"Message sent (id={msg_id}).")


# List messages (optionally filtered by user).
@app.command()
def inbox(with_user: Optional[str] = typer.Option(None, "--with")):
    state = _state()
    auth = _require_auth(state)
    url = f"{_backend_url(state)}/api/messages"
    if with_user:
        with_user = _resolve_alias(state, with_user)
        url = f"{url}?with={with_user}"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Inbox failed: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    messages = resp.json()
    if not messages:
        console.print("No messages.")
        return
    rows = []
    for msg in messages:
        rows.append([
            str(msg.get("id", "")),
            msg.get("created_at", ""),
            msg.get("sender", ""),
            msg.get("recipient", ""),
        ])
    _render_table("Messages", ["Id", "Time", "From", "To"], rows)


# Read and decrypt a conversation with a given user.
@app.command()
def read(with_user: str):
    state = _state()
    auth = _require_auth(state)
    password = typer.prompt("Password", hide_input=True)
    with_user = _resolve_alias(state, with_user)

    try:
        private_key = _load_private_key_from_state(state, password)
    except Exception:
        typer.secho("Failed to decrypt private key.", fg=typer.colors.RED)
        raise typer.Exit(1)

    url = f"{_backend_url(state)}/api/messages?with={with_user}"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Read failed: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    messages = resp.json()
    history = _load_history()
    rows = []
    for msg in messages:
        msg_id = str(msg.get("id", "?"))
        if msg["recipient"] == auth["username"]:
            try:
                plaintext = _decrypt_message(msg["ciphertext"], msg["iv"], msg["encrypted_key"], private_key)
                plaintext = _message_content(plaintext)["display"]
            except Exception:
                plaintext = "[decryption failed]"
        else:
            plaintext = _history_display(history, msg.get("id"))
        rows.append([msg_id, msg["created_at"], msg["sender"], msg["recipient"], plaintext])
    _render_table(f"Conversation with {with_user}", ["Id", "Time", "From", "To", "Message"], rows)


# Chat flow with simple paging and reply loop.
def _chat_flow(
    state: dict,
    auth: dict,
    with_user: str,
    private_key: Optional[x25519.X25519PrivateKey],
) -> None:
    url = f"{_backend_url(state)}/api/messages?with={with_user}"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Chat failed: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    messages = resp.json()
    if not messages:
        console.print("No messages in this conversation.")
        return

    messages.sort(key=lambda msg: msg.get("created_at", ""))
    history = _load_history()
    # Page from the end by default (last 20 messages).
    page_size = 20
    start_index = max(len(messages) - page_size, 0)

    while True:
        page = messages[start_index:]
        rows = _conversation_rows(page, auth["username"], private_key, history)
        _render_table(f"Conversation with {with_user}", ["Id", "Time", "From", "To", "Message"], rows)

        if start_index == 0:
            console.print("No older messages.")

        choice = _prompt_choice("chat (r=reply, m=more, q=quit)", {"r", "m", "q"}, default="q")
        if choice == "q":
            return
        if choice == "m":
            if start_index == 0:
                continue
            start_index = max(start_index - page_size, 0)
            continue
        if choice == "r":
            attachment_path = typer.prompt("Image path (leave blank for text)", default="", show_default=False).strip()
            if attachment_path:
                caption = typer.prompt("Caption (optional)", default="", show_default=False).strip()
                send(with_user, caption or None, file=Path(attachment_path))
                continue
            message = typer.prompt("Message").strip()
            if not message:
                typer.secho("Message required.", fg=typer.colors.RED)
                continue
            send(with_user, message)


# Shortcut to chat with a user.
@app.command()
def chat(with_user: str):
    state = _state()
    auth = _require_auth(state)
    with_user = _resolve_alias(state, with_user)
    private_key = _unlock_private_key_once(state)
    _chat_flow(state, auth, with_user, private_key)


# Append a plaintext history entry if enabled.
def _append_history(entry: dict, save_history: bool = True) -> None:
    if not save_history:
        return
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")
    if os.name != "nt":
        HISTORY_FILE.chmod(0o600)


# Load plaintext history into a lookup map.
def _load_history() -> dict:
    history = {}
    if not HISTORY_FILE.exists():
        return history
    for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
            parsed = _history_entry_from_record(entry)
            if parsed is not None:
                history[str(entry["id"])] = parsed
        except json.JSONDecodeError:
            continue
    return history


if __name__ == "__main__":
    app()
