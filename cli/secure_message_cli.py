import base64
import inspect
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests
import typer
import click
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization

app = typer.Typer(add_completion=False, no_args_is_help=True)
config_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")

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


def _require_auth(state: dict) -> dict:
    auth = state.get("auth") or {}
    token = auth.get("token")
    username = auth.get("username")
    if not token or not username:
        typer.secho("Not logged in. Run: login <username>", fg=typer.colors.RED)
        raise typer.Exit(1)
    return auth


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
        url = f"{url}?with={with_user}"
    resp = _request("GET", url, token=auth["token"])
    if resp.status_code != 200:
        typer.secho(f"Inbox failed: {resp.text}", fg=typer.colors.RED)
        raise typer.Exit(1)

    messages = resp.json()
    typer.echo(json.dumps(messages, indent=2))


@app.command()
def read(with_user: str):
    state = _state()
    auth = _require_auth(state)
    password = typer.prompt("Password", hide_input=True)

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
    for msg in messages:
        if msg["recipient"] == auth["username"]:
            try:
                plaintext = _decrypt_message(msg["ciphertext"], msg["iv"], msg["encrypted_key"], private_key)
            except Exception:
                plaintext = "[decryption failed]"
        else:
            plaintext = history.get(str(msg["id"]), "[sent message not stored locally]")

        typer.echo(f"{msg['created_at']} {msg['sender']} -> {msg['recipient']}: {plaintext}")


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
