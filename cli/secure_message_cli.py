import base64
import inspect
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

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

console = Console(force_terminal=False)

STATE_DIR = Path.home() / ".secure-message-cli"
STATE_FILE = STATE_DIR / "state.json"
HISTORY_FILE = STATE_DIR / "history.jsonl"

DEFAULT_BACKEND_URL = "http://localhost:8080"
PBKDF2_ITERATIONS = 200_000

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


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _state() -> dict:
    if not STATE_FILE.exists():
        return {"backend_url": DEFAULT_BACKEND_URL, "auth": {}, "keys": {}}
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def _save_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _backend_url(state: dict) -> str:
    return state.get("backend_url") or DEFAULT_BACKEND_URL


def _contacts(state: dict) -> dict:
    return state.get("contacts") or {}


def _resolve_alias(state: dict, name: str) -> str:
    contacts = _contacts(state)
    return contacts.get(name, name)


def _require_auth(state: dict) -> dict:
    auth = state.get("auth") or {}
    token = auth.get("token")
    username = auth.get("username")
    if not token or not username:
        typer.secho("Not logged in. Run: login <username>", fg=typer.colors.RED)
        raise typer.Exit(1)
    return auth


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


def _auth_valid(auth: dict) -> bool:
    token = auth.get("token")
    username = auth.get("username")
    expires_at = _parse_expires_at(auth.get("expires_at"))
    if not token or not username:
        return False
    if expires_at and datetime.now(timezone.utc) >= expires_at:
        return False
    return True


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


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


def _decrypt_private_key(encrypted_payload: str, password: str) -> bytes:
    data = json.loads(encrypted_payload)
    salt = _b64decode(data["salt"])
    nonce = _b64decode(data["nonce"])
    ciphertext = _b64decode(data["ciphertext"])
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None)


def _generate_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def _serialize_public_key(public_key: x25519.X25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(raw)


def _serialize_private_key(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_private_key_from_state(state: dict, password: str) -> x25519.X25519PrivateKey:
    encrypted_payload = state.get("keys", {}).get("encrypted_private_key")
    if not encrypted_payload:
        typer.secho("No local private key found. Login to fetch it.", fg=typer.colors.RED)
        raise typer.Exit(1)
    private_bytes = _decrypt_private_key(encrypted_payload, password)
    return x25519.X25519PrivateKey.from_private_bytes(private_bytes)


def _encrypt_message(plaintext: str, recipient_public_b64: str) -> tuple[str, str, str]:
    recipient_public = x25519.X25519PublicKey.from_public_bytes(_b64decode(recipient_public_b64))
    eph_private = x25519.X25519PrivateKey.generate()
    eph_public = eph_private.public_key()

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


def _decrypt_message(ciphertext_b64: str, iv_b64: str, encrypted_key_payload: str, private_key: x25519.X25519PrivateKey) -> str:
    data = json.loads(encrypted_key_payload)
    eph_public = x25519.X25519PublicKey.from_public_bytes(_b64decode(data["epk"]))
    salt = _b64decode(data["salt"])

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


def _request(method: str, url: str, token: Optional[str] = None, **kwargs):
    headers = kwargs.pop("headers", {})
    headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return requests.request(method, url, headers=headers, timeout=15, **kwargs)


def _prompt_choice(prompt: str, valid: set[str], default: Optional[str] = None) -> str:
    try:
        return _prompt_choice_ptk(prompt, valid, default)
    except Exception:
        return _prompt_choice_typer(prompt, valid, default)


def _prompt_choice_typer(prompt: str, valid: set[str], default: Optional[str]) -> str:
    while True:
        choice = typer.prompt(prompt, default=default) if default is not None else typer.prompt(prompt)
        choice = choice.strip()
        if choice in valid:
            return choice
        typer.secho(f"Invalid choice: {choice}", fg=typer.colors.RED)


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


def _launch_shell_window(script_path: Path) -> bool:
    cmd = [sys.executable, str(script_path), "shell"]
    if os.name == "nt":
        try:
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_CONSOLE)
            return True
        except Exception:
            return False
    return False


def _render_status(title: str, lines: list[str]) -> None:
    if not lines:
        return
    body = "\n".join(lines)
    console.print(Panel(body, title=title, box=box.SIMPLE, expand=False))


def _render_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, box=box.SIMPLE, show_lines=False)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.print(table)


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


def _fetch_messages(state: dict, auth: dict) -> list[dict]:
    url = f"{_backend_url(state)}/api/messages"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Failed to fetch messages: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)
    return resp.json()


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
    _render_table(f"Conversation with {with_user}", ["Time", "From", "To", "Message"], rows)


def _conversation_rows(
    convo: list[dict],
    username: str,
    private_key: Optional[x25519.X25519PrivateKey],
    history: dict,
) -> list[list[str]]:
    rows = []
    for msg in convo:
        sender = msg.get("sender", "unknown")
        recipient = msg.get("recipient", "unknown")
        created_at = msg.get("created_at", "unknown")
        if recipient == username:
            if private_key is None:
                plaintext = "[inbox locked]"
            else:
                try:
                    plaintext = _decrypt_message(
                        msg.get("ciphertext", ""),
                        msg.get("iv", ""),
                        msg.get("encrypted_key", ""),
                        private_key,
                    )
                except Exception:
                    plaintext = "[decryption failed]"
        else:
            plaintext = history.get(str(msg.get("id")), "[sent message not stored locally]")
        rows.append([created_at, sender, recipient, plaintext])
    return rows


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


@config_app.command("set-url")
def config_set_url(url: str):
    state = _state()
    state["backend_url"] = url.rstrip("/")
    _save_state(state)
    typer.echo(f"Backend URL set to {state['backend_url']}")


@config_app.command("show")
def config_show():
    state = _state()
    typer.echo(json.dumps(state, indent=2))


@contacts_app.command("add")
def contacts_add(alias: str, username: str):
    state = _state()
    contacts = _contacts(state)
    contacts[alias] = username
    state["contacts"] = contacts
    _save_state(state)
    console.print(f"Saved contact {alias} -> {username}")


@contacts_app.command("list")
def contacts_list():
    state = _state()
    contacts = _contacts(state)
    if not contacts:
        console.print("No contacts saved.")
        return
    rows = [[alias, username] for alias, username in sorted(contacts.items())]
    _render_table("Contacts", ["Alias", "Username"], rows)


@contacts_app.command("remove")
def contacts_remove(alias: str):
    state = _state()
    contacts = _contacts(state)
    if alias not in contacts:
        typer.secho("Alias not found.", fg=typer.colors.RED)
        raise typer.Exit(1)
    contacts.pop(alias, None)
    state["contacts"] = contacts
    _save_state(state)
    console.print(f"Removed contact {alias}.")


def _safe_call(func, *args) -> bool:
    try:
        func(*args)
        return True
    except typer.Exit:
        return False


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        launcher()


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


@app.command()
def register(username: str):
    state = _state()
    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)

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
        typer.secho(f"Register failed: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    state["keys"] = {
        "public_key": public_key_b64,
        "encrypted_private_key": encrypted_private_key,
    }
    _save_state(state)
    typer.echo("Registered. Run 'login <username>' to get a token.")


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

    me_url = f"{_backend_url(state)}/api/me"
    me_resp = _request("GET", me_url, token=token)
    if me_resp.status_code != 200:
        typer.secho(f"Login succeeded but failed to fetch /api/me: {me_resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    me = me_resp.json()
    state["auth"] = {"token": token, "username": username, "expires_at": expires_at.isoformat()}
    state["keys"] = {
        "public_key": me["public_key"],
        "encrypted_private_key": me["encrypted_private_key"],
    }
    _save_state(state)

    # Validate password can decrypt the key
    try:
        _decrypt_private_key(state["keys"]["encrypted_private_key"], password)
    except Exception:
        typer.secho("Warning: password could not decrypt private key.", fg=typer.colors.YELLOW)

    typer.echo("Login ok.")


@app.command()
def shell():
    state = _state()
    auth = state.get("auth") or {}
    if not _auth_valid(auth):
        typer.secho("Not logged in. Run the launcher to login.", fg=typer.colors.RED)
        raise typer.Exit(1)

    username = auth["username"]
    private_key = _unlock_private_key_once(state)
    while True:
        typer.echo("")
        _print_menu(
            title="Secure Message Session",
            options=[("1", "Send message"), ("2", "View messages"), ("3", "Chat"), ("4", "Exit")],
            info_lines=[f"User: {username}", f"Backend: {_backend_url(state)}"],
            footer_lines=["Press 1-4"],
        )
        choice = _prompt_choice(f"{username}@secure>", {"1", "2", "3", "4"}, default="4")

        if choice == "1":
            recipient = typer.prompt("Recipient").strip()
            if not recipient:
                typer.secho("Recipient required.", fg=typer.colors.RED)
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
        raise typer.Exit()


@app.command()
def whoami():
    state = _state()
    auth = state.get("auth") or {}
    if auth.get("username"):
        typer.echo(auth["username"])
    else:
        typer.echo("not logged in")


@app.command()
def logout():
    state = _state()
    state["auth"] = {}
    _save_state(state)
    typer.echo("Logged out.")


@app.command()
def send(recipient: str, message: str):
    state = _state()
    auth = _require_auth(state)
    recipient = _resolve_alias(state, recipient)

    password = typer.prompt("Password", hide_input=True)
    try:
        private_key = _load_private_key_from_state(state, password)
    except Exception:
        typer.secho("Failed to decrypt private key.", fg=typer.colors.RED)
        raise typer.Exit(1)

    # Fetch recipient public key
    url = f"{_backend_url(state)}/api/users/{recipient}/public-key"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Failed to fetch public key: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    recipient_public_key = resp.json()["public_key"]
    encrypted_key, ciphertext, iv = _encrypt_message(message, recipient_public_key)

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
    _append_history({
        "id": msg_id,
        "sender": auth["username"],
        "recipient": recipient,
        "plaintext": message,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    typer.echo(f"Message sent (id={msg_id}).")


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
        if msg["recipient"] == auth["username"]:
            try:
                plaintext = _decrypt_message(msg["ciphertext"], msg["iv"], msg["encrypted_key"], private_key)
            except Exception:
                plaintext = "[decryption failed]"
        else:
            plaintext = history.get(str(msg["id"]), "[sent message not stored locally]")
        rows.append([msg["created_at"], msg["sender"], msg["recipient"], plaintext])
    _render_table(f"Conversation with {with_user}", ["Time", "From", "To", "Message"], rows)


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
    page_size = 20
    start_index = max(len(messages) - page_size, 0)

    while True:
        page = messages[start_index:]
        rows = _conversation_rows(page, auth["username"], private_key, history)
        _render_table(f"Conversation with {with_user}", ["Time", "From", "To", "Message"], rows)

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
            message = typer.prompt("Message").strip()
            if not message:
                typer.secho("Message required.", fg=typer.colors.RED)
                continue
            send(with_user, message)


@app.command()
def chat(with_user: str):
    state = _state()
    auth = _require_auth(state)
    with_user = _resolve_alias(state, with_user)
    private_key = _unlock_private_key_once(state)
    _chat_flow(state, auth, with_user, private_key)


def _append_history(entry: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def _load_history() -> dict:
    history = {}
    if not HISTORY_FILE.exists():
        return history
    for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
            if "id" in entry and "plaintext" in entry:
                history[str(entry["id"])] = entry["plaintext"]
        except json.JSONDecodeError:
            continue
    return history


if __name__ == "__main__":
    app()
