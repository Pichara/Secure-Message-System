from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual import work
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.timer import Timer
from textual.widgets import Button, Footer, Header, Input, ListItem, ListView, RichLog, Static

from secure_message_cli import (
    STATE_DIR,
    _append_history,
    _auth_valid,
    _b64decode,
    _backend_url,
    _build_attachment_envelope,
    _decrypt_message,
    _encrypt_message,
    _encrypt_private_key,
    _format_message_log_line,
    _generate_keypair,
    _history_display,
    _load_history,
    _load_private_key_from_state,
    _message_content,
    _request,
    _resolve_alias,
    _serialize_private_key,
    _serialize_public_key,
    _state,
    _save_state,
    _write_attachment_file,
)


@dataclass
class AuthState:
    token: str
    username: str
    role: str = "user"
    private_key: object | None = None


PASSWORD_RULE_HINT = "Password must be 8-128 characters and include at least one number and one special character."


def _is_dedicated_admin(auth: AuthState) -> bool:
    return auth.role == "admin"


def _registration_password_message(password: str) -> Optional[str]:
    """Mirror the stronger registration policy locally for immediate TUI feedback."""
    if len(password) < 8 or len(password) > 128:
        return PASSWORD_RULE_HINT
    if not any(ch.isdigit() for ch in password):
        return PASSWORD_RULE_HINT
    if not any((not ch.isalnum()) and (not ch.isspace()) for ch in password):
        return PASSWORD_RULE_HINT
    return None


def _format_plaintext(plaintext: str) -> str:
    """Render text messages normally and attachment envelopes as compact metadata."""
    return str(_message_content(plaintext).get("display") or plaintext)


class UserListScreen(ModalScreen[None]):
    """Read-only modal for the admin-only user list."""

    CSS = """
    #user-list-dialog {
        width: 70%;
        min-width: 40;
        height: auto;
        max-height: 80%;
        padding: 1 2;
        border: round #4c4c4c;
    }
    #user-list-log {
        height: 16;
        border: round #4c4c4c;
        margin: 1 0;
    }
    #user-list-actions {
        height: auto;
    }
    """

    def __init__(self, usernames: list[str]) -> None:
        super().__init__()
        self._usernames = usernames

    def compose(self) -> ComposeResult:
        with Container(id="user-list-dialog"):
            yield Static("Registered Users", id="user-list-title")
            yield RichLog(id="user-list-log", wrap=True)
            with Horizontal(id="user-list-actions"):
                yield Button("Close", id="close", variant="primary")

    def on_mount(self) -> None:
        log = self.query_one("#user-list-log", RichLog)
        if not self._usernames:
            log.write("No users returned.")
            return
        for username in self._usernames:
            log.write(username)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close":
            self.dismiss(None)


class InputDialog(ModalScreen[str]):
    """Small modal prompt returning a single (optionally secret) string value."""

    def __init__(self, title: str, placeholder: str = "", password: bool = False) -> None:
        super().__init__()
        self._title = title
        self._placeholder = placeholder
        self._password = password

    def compose(self) -> ComposeResult:
        """Render a simple title + input + OK/Cancel action row."""
        with Container(id="dialog"):
            yield Static(self._title, id="dialog-title")
            yield Input(placeholder=self._placeholder, password=self._password, id="dialog-input")
            with Horizontal(id="dialog-actions"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        """Focus the input immediately so Enter works without extra clicks."""
        self.query_one(Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with input value on OK; dismiss with empty string on Cancel."""
        if event.button.id == "ok":
            value = self.query_one(Input).value.strip()
            self.dismiss(value)
        else:
            self.dismiss("")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Treat Enter as OK (submit the current input value)."""
        value = event.value.strip()
        self.dismiss(value)


class NewChatDialog(ModalScreen[str]):
    """Centered modal that validates the target username before closing."""

    CSS = """
    #new-chat-dialog {
        width: 60%;
        min-width: 40;
        height: auto;
        padding: 1 2;
        border: round #4c4c4c;
    }
    #new-chat-status {
        width: 100%;
        content-align: center middle;
        color: #ffb0b0;
        margin-bottom: 1;
    }
    #new-chat-title {
        width: 100%;
        content-align: center middle;
    }
    #new-chat-actions {
        height: auto;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="new-chat-dialog"):
            yield Static("", id="new-chat-status")
            yield Static("Start chat with", id="new-chat-title")
            yield Input(placeholder="username", id="new-chat-input")
            with Horizontal(id="new-chat-actions"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#new-chat-input", Input).focus()

    def _set_status(self, message: str) -> None:
        self.query_one("#new-chat-status", Static).update(message)

    def _submit(self) -> None:
        username = self.query_one("#new-chat-input", Input).value.strip()
        if not username:
            self._set_status("Username required.")
            return

        state = _state()
        username = _resolve_alias(state, username)
        auth = state.get("auth") or {}
        resp = _request(
            "GET",
            f"{_backend_url(state)}/api/users/{username}/public-key",
            token=auth.get("token"),
        )
        if resp.status_code == 200:
            self.dismiss(username)
            return
        if resp.status_code == 404:
            self._set_status("User not found!")
            return
        if resp.status_code == 401:
            self._set_status("Session expired. Please login again.")
            return
        self._set_status(f"Failed to resolve user: {resp.text}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self._submit()
            return
        self.dismiss("")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()


class AttachFileDialog(ModalScreen[str]):
    """Centered modal that validates the selected file path before closing."""

    CSS = """
    #attach-file-dialog {
        width: 60%;
        min-width: 40;
        height: auto;
        padding: 1 2;
        border: round #4c4c4c;
    }
    #attach-file-status {
        width: 100%;
        content-align: center middle;
        color: #ffb0b0;
        margin-bottom: 1;
    }
    #attach-file-title {
        width: 100%;
        content-align: center middle;
    }
    #attach-file-actions {
        height: auto;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="attach-file-dialog"):
            yield Static("", id="attach-file-status")
            yield Static("Attach file", id="attach-file-title")
            yield Input(placeholder="C:\\path\\to\\file.ext", id="attach-file-input")
            with Horizontal(id="attach-file-actions"):
                yield Button("OK", id="ok", variant="primary")
                yield Button("Cancel", id="cancel")

    def on_mount(self) -> None:
        self.query_one("#attach-file-input", Input).focus()

    def _set_status(self, message: str) -> None:
        self.query_one("#attach-file-status", Static).update(message)

    def _submit(self) -> None:
        raw_path = self.query_one("#attach-file-input", Input).value.strip()
        if not raw_path:
            self._set_status("File path required.")
            return

        file_path = Path(raw_path).expanduser()
        if not file_path.exists():
            self._set_status("File not found.")
            return
        if not file_path.is_file():
            self._set_status("Path must be a file.")
            return

        self.dismiss(str(file_path))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ok":
            self._submit()
            return
        self.dismiss("")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()


class AuthScreen(Screen):
    """Login/register screen that also seeds local state with key material."""

    CSS = """
    #auth {
        width: 60%;
        min-width: 40;
        height: auto;
        margin: 3 10;
        padding: 1 2;
        border: round #4c4c4c;
    }
    #auth-actions {
        width: 100%;
        height: auto;
        margin-top: 1;
    }
    #auth-status {
        color: #b0b0b0;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        """Render username/password fields and login/register controls."""
        yield Header()
        with Container(id="auth"):
            yield Static("Secure Message", id="auth-title")
            yield Input(placeholder="Username", id="auth-username")
            yield Input(placeholder="Password", password=True, id="auth-password")
            yield Input(placeholder="Confirm password (register)", password=True, id="auth-confirm")
            with Horizontal(id="auth-actions"):
                yield Button("Login", id="login", variant="primary")
                yield Button("Register", id="register")
                yield Button("Quit", id="quit")
            yield Static("", id="auth-status")
        yield Footer()

    def on_mount(self) -> None:
        """Focus the first field on entry."""
        self.query_one("#auth-username", Input).focus()

    def _set_status(self, message: str) -> None:
        """Update the status line with the latest auth-related message."""
        self.query_one("#auth-status", Static).update(message)

    def _login(self, username: str, password: str) -> Optional[AuthState]:
        """Authenticate, persist token + key blobs to disk, and return an active session."""
        state = _state()
        url = f"{_backend_url(state)}/api/login"
        resp = _request("POST", url, json={"username": username, "password": password})
        if resp.status_code != 200:
            self._set_status(f"Login failed: {resp.text}")
            return None

        data = resp.json()
        token = data["token"]
        expires_in = int(data.get("expires_in", 3600))
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        # After login, fetch the caller's public key + encrypted private key stored on the server.
        me_url = f"{_backend_url(state)}/api/me"
        me_resp = _request("GET", me_url, token=token)
        if me_resp.status_code != 200:
            self._set_status(f"Login ok, /api/me failed: {me_resp.text}")
            return None

        me = me_resp.json()
        role = me.get("role") or "user"
        state["auth"] = {
            "token": token,
            "username": username,
            "expires_at": expires_at.isoformat(),
            "role": role,
        }
        state["keys"] = {
            "public_key": me["public_key"],
            "encrypted_private_key": me["encrypted_private_key"],
        }
        private_key = None
        if role != "admin":
            try:
                private_key = _load_private_key_from_state(state, password)
            except Exception:
                self._set_status("Login ok, but failed to decrypt the local private key.")
                return None
        _save_state(state)
        return AuthState(token=token, username=username, role=role, private_key=private_key)

    def _register(self, username: str, password: str, confirm: str) -> bool:
        """Register a user by generating a keypair and uploading only public + encrypted private key."""
        if password != confirm:
            self._set_status("Password confirmation does not match.")
            return False
        password_message = _registration_password_message(password)
        if password_message:
            self._set_status(password_message)
            return False
        state = _state()
        private_key, public_key = _generate_keypair()
        payload = {
            "username": username,
            "password": password,
            "public_key": _serialize_public_key(public_key),
            # Private key never leaves the client unencrypted; server stores this blob as opaque data.
            "encrypted_private_key": _encrypt_private_key(_serialize_private_key(private_key), password),
        }
        url = f"{_backend_url(state)}/api/register"
        resp = _request("POST", url, json=payload)
        if resp.status_code != 201:
            message = resp.text
            try:
                data = resp.json()
                if data.get("error") == "invalid_password":
                    message = data.get("message") or PASSWORD_RULE_HINT
                elif data.get("error") == "registration_failed":
                    message = "Registration failed."
            except Exception:
                pass
            self._set_status(f"Register failed: {message}")
            return False
        state["keys"] = {
            "public_key": payload["public_key"],
            "encrypted_private_key": payload["encrypted_private_key"],
        }
        _save_state(state)
        return True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle login/register/quit button actions."""
        if event.button.id == "quit":
            self.app.exit()
            return

        username = self.query_one("#auth-username", Input).value.strip()
        password = self.query_one("#auth-password", Input).value
        confirm = self.query_one("#auth-confirm", Input).value
        if not username or not password:
            self._set_status("Username and password required.")
            return

        if event.button.id == "register":
            if not self._register(username, password, confirm):
                return

        if event.button.id in {"login", "register"}:
            auth = self._login(username, password)
            if not auth:
                return
            if _is_dedicated_admin(auth):
                self.app.push_screen(AdminDirectoryScreen(auth))
                return
            self.app.push_screen(MessageScreen(auth))


class AdminDirectoryScreen(Screen):
    """Read-only ADMIN view that only lists registered users."""

    BINDINGS = [
        ("r", "refresh", "Refresh"),
        ("l", "logout", "Logout"),
    ]

    CSS = """
    #admin-directory {
        width: 70%;
        min-width: 48;
        height: auto;
        margin: 3 10;
        padding: 1 2;
        border: round #4c4c4c;
    }
    #admin-session-meta {
        color: #b0b0b0;
        margin-bottom: 1;
    }
    #admin-user-log {
        height: 18;
        border: round #4c4c4c;
        margin: 1 0;
    }
    #admin-actions {
        height: auto;
    }
    #admin-status {
        color: #b0b0b0;
        margin-top: 1;
    }
    """

    def __init__(self, auth: AuthState) -> None:
        super().__init__()
        self.auth = auth

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="admin-directory"):
            yield Static("", id="admin-session-meta")
            yield Static("Registered Users", id="admin-title")
            yield RichLog(id="admin-user-log", wrap=True)
            with Horizontal(id="admin-actions"):
                yield Button("Refresh", id="refresh", variant="primary")
                yield Button("Logout", id="logout")
        yield Static("", id="admin-status")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#admin-session-meta", Static).update(
            f"Signed in as {self.auth.username} (admin)"
        )
        self.action_refresh()

    def _set_status(self, message: str) -> None:
        self.query_one("#admin-status", Static).update(message)

    def _show_users(self, usernames: list[str]) -> None:
        log = self.query_one("#admin-user-log", RichLog)
        log.clear()
        if not usernames:
            log.write("No users returned.")
            return
        for username in usernames:
            log.write(username)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            self.action_refresh()
            return
        if event.button.id == "logout":
            self.action_logout()

    def action_refresh(self) -> None:
        state = _state()
        auth = state.get("auth") or {}
        resp = _request(
            "GET",
            f"{_backend_url(state)}/api/admin/users",
            token=auth.get("token"),
        )
        if resp.status_code == 401:
            self._set_status("Session expired. Please login again.")
            self.app.push_screen(AuthScreen())
            return
        if resp.status_code == 403:
            self._set_status("Admin access denied by server.")
            return
        if resp.status_code != 200:
            self._set_status(f"Failed to load users: {resp.text}")
            return

        payload = resp.json()
        raw_users = payload.get("users", payload)
        usernames: list[str] = []
        if isinstance(raw_users, list):
            for entry in raw_users:
                if isinstance(entry, dict) and entry.get("username"):
                    usernames.append(str(entry["username"]))
                elif isinstance(entry, str):
                    usernames.append(entry)

        usernames.sort()
        self._show_users(usernames)
        self._set_status(f"Loaded {len(usernames)} users.")

    def action_logout(self) -> None:
        state = _state()
        state["auth"] = {}
        _save_state(state)
        self.app.push_screen(AuthScreen())


class MessageScreen(Screen):
    """Main messaging UI: contacts on the left, conversation + compose on the right."""

    BINDINGS = [
        ("n", "new_chat", "New chat"),
        ("r", "refresh", "Refresh"),
        ("l", "logout", "Logout"),
    ]

    CSS = """
    #main {
        height: 1fr;
    }
    #sidebar {
        width: 30%;
        min-width: 24;
        border: round #4c4c4c;
    }
    #details {
        height: 8;
        border-top: solid #4c4c4c;
        padding: 1 1;
    }
    #contact-actions {
        height: 3;
        margin-bottom: 1;
    }
    #session-meta {
        margin-bottom: 1;
        color: #b0b0b0;
    }
    #messages {
        width: 70%;
        border: round #4c4c4c;
    }
    #message-log {
        height: 1fr;
    }
    .message-line {
        width: 100%;
        padding: 0 1;
    }
    .message-attachment {
        width: 100%;
        margin: 0 1 1 1;
        text-align: left;
    }
    #compose-box {
        height: auto;
        margin-top: 1;
    }
    #compose {
        height: 3;
        border: round #4c4c4c;
    }
    #compose-actions {
        height: 3;
        margin-top: 1;
    }
    #status {
        height: 1;
        color: #b0b0b0;
        margin-top: 1;
    }
    """

    def __init__(self, auth: AuthState) -> None:
        """Initialize per-screen session state (token + in-memory decrypted private key)."""
        super().__init__()
        self.auth = auth
        self.private_key = auth.private_key
        self.current_with: Optional[str] = None
        self._chat_refresh_timer: Timer | None = None
        self._last_conversation_signature: tuple[int, str] | None = None

    def _can_view_admin_users(self) -> bool:
        """Any admin session can open the read-only user list view."""
        return self.auth.role == "admin"

    def compose(self) -> ComposeResult:
        """Render sidebar contact list, message log, and compose box."""
        yield Header()
        with Horizontal(id="main"):
            with Container(id="sidebar"):
                yield Static("Contacts", id="sidebar-title")
                yield Static("", id="session-meta")
                with Horizontal(id="contact-actions"):
                    yield Button("New chat", id="new-chat", variant="primary")
                    if self._can_view_admin_users():
                        yield Button("Users", id="admin-users")
                yield ListView(id="contact-list")
                yield Static("No contact selected.", id="details")
            with Vertical(id="messages"):
                yield VerticalScroll(id="message-log")
                with Container(id="compose-box"):
                    yield Input(placeholder="Type message and press Enter", id="compose")
                    with Horizontal(id="compose-actions"):
                        yield Button("Attach file", id="attach-file")
                        yield Button("Refresh", id="refresh")
                        yield Button("Logout", id="logout")
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        """Disable compose until a conversation is loaded; then render contacts."""
        self.query_one("#compose", Input).disabled = True
        self._update_session_meta()
        self._refresh_contacts()
        self._chat_refresh_timer = self.set_interval(2.0, self._auto_refresh_active_chat, pause=False)

    def on_unmount(self) -> None:
        if self._chat_refresh_timer is not None:
            self._chat_refresh_timer.stop()
            self._chat_refresh_timer = None

    def _set_status(self, message: str) -> None:
        """Update the transient status line at the bottom of the screen."""
        self.query_one("#status", Static).update(message)

    def _update_session_meta(self) -> None:
        """Show the active user and role near the contact list."""
        role_label = "admin" if self.auth.role == "admin" else "user"
        self.query_one("#session-meta", Static).update(f"Signed in as {self.auth.username} ({role_label})")

    def _load_contacts(self) -> list[dict[str, str]]:
        """Fetch the current user's saved contacts from the backend."""
        state = _state()
        auth = state.get("auth") or {}
        resp = _request(
            "GET",
            f"{_backend_url(state)}/api/contacts",
            token=auth.get("token"),
        )
        if resp.status_code == 401:
            self._set_status("Session expired. Please login again.")
            self.app.push_screen(AuthScreen())
            return []
        if resp.status_code != 200:
            self._set_status(f"Failed to load contacts: {resp.text}")
            return []

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

    def _refresh_contacts(self) -> None:
        """Re-render the sidebar contact list from the backend."""
        state = _state()
        auth = state.get("auth") or {}
        if not _auth_valid(auth):
            self.app.push_screen(AuthScreen())
            return

        contacts = self._load_contacts()
        list_view = self.query_one("#contact-list", ListView)
        list_view.clear()

        for contact in contacts:
            alias = contact["alias"]
            username = contact["username"]
            label = f"{alias} ({username})" if alias != username else username
            item = ListItem(Static(label))
            item.user = username
            item.alias = alias
            list_view.append(item)

        if not contacts:
            self._set_status("No contacts yet. Press 'n' to add one.")

    def _fetch_conversation_messages(self, with_user: str) -> Optional[list[dict]]:
        """Fetch the current conversation payload from the backend."""
        state = _state()
        auth = state.get("auth") or {}

        resp = _request(
            "GET",
            f"{_backend_url(state)}/api/messages?with={with_user}",
            token=auth.get("token"),
        )
        if resp.status_code != 200:
            if resp.status_code == 401:
                self._set_status("Session expired. Please login again.")
                self.app.push_screen(AuthScreen())
                return
            if resp.status_code == 404:
                self._set_status("User not found.")
            else:
                self._set_status(f"Failed to load messages: {resp.text}")
            self.query_one("#compose", Input).disabled = True
            return None

        messages = resp.json()
        messages.sort(key=lambda msg: msg.get("created_at", ""))
        return messages

    def _conversation_signature(self, messages: list[dict]) -> tuple[int, str]:
        if not messages:
            return (0, "")
        last = messages[-1]
        return (len(messages), str(last.get("created_at", "")))

    def _render_message_widget(self, message_line: str, parsed_content: dict, message_id: object) -> None:
        log = self.query_one("#message-log", VerticalScroll)
        if parsed_content.get("kind") == "attachment" and parsed_content.get("bytes_b64"):
            button = Button(message_line, id=f"attachment-msg-{message_id}", classes="message-attachment")
            button.attachment_content = parsed_content
            log.mount(button)
            return
        log.mount(Static(message_line, classes="message-line"))

    def _save_attachment_from_content(self, content: dict) -> Optional[Path]:
        try:
            raw_bytes = _b64decode(str(content.get("bytes_b64") or ""))
        except Exception:
            self._set_status("Attachment payload is invalid.")
            return None

        download_dir = Path.home() / "Downloads"
        saved_path = _write_attachment_file(download_dir, str(content.get("name") or "attachment.bin"), raw_bytes)
        self._set_status(f"Attachment saved to {saved_path}.")
        return saved_path

    def _render_conversation(self, with_user: str, messages: Optional[list[dict]] = None, *, update_status: bool = True) -> None:
        """Render decrypted/plaintext view for the active conversation."""
        if messages is None:
            messages = self._fetch_conversation_messages(with_user)
            if messages is None:
                return

        state = _state()
        auth = state.get("auth") or {}
        history = _load_history()
        history_map = history if isinstance(history, dict) else {}
        self._last_conversation_signature = self._conversation_signature(messages)
        log = self.query_one("#message-log", VerticalScroll)
        for child in list(log.children):
            child.remove()
        if not messages:
            log.mount(Static("No messages yet. Send one below.", classes="message-line"))
        for msg in messages:
            sender = msg.get("sender", "unknown")
            recipient = msg.get("recipient", "unknown")
            created_at = msg.get("created_at", "unknown")
            if recipient == auth.get("username"):
                if self.private_key is None:
                    parsed_content = {"kind": "text", "display": "[message unavailable]"}
                else:
                    try:
                        plaintext = _decrypt_message(
                            msg.get("ciphertext", ""),
                            msg.get("iv", ""),
                            msg.get("encrypted_key", ""),
                            self.private_key,
                        )
                        parsed_content = _message_content(plaintext)
                    except Exception:
                        parsed_content = {"kind": "text", "display": "[decryption failed]"}
            else:
                # Sent-message plaintext is only stored locally (optional); server stores ciphertext only.
                parsed_content = history_map.get(str(msg.get("id"))) or {
                    "kind": "text",
                    "display": _history_display(history_map, msg.get("id")),
                }
            self._render_message_widget(
                _format_message_log_line(
                    created_at,
                    sender,
                    recipient,
                    str(parsed_content.get("display") or ""),
                ),
                parsed_content,
                msg.get("id"),
            )

        self.query_one("#compose", Input).disabled = False
        self.query_one("#compose", Input).focus()
        self._render_contact_details(with_user, messages)
        if update_status:
            self._set_status(f"Chatting with {with_user}")

    def _auto_refresh_active_chat(self) -> None:
        """Poll the active conversation and update the log when new messages arrive."""
        if not self.current_with:
            return
        if self.screen is not self:
            return

        messages = self._fetch_conversation_messages(self.current_with)
        if messages is None:
            return

        signature = self._conversation_signature(messages)
        if signature == self._last_conversation_signature:
            return

        self._render_conversation(self.current_with, messages, update_status=False)
        self._set_status(f"New messages in chat with {self.current_with}.")

    def _shorten(self, value: str, keep: int = 6) -> str:
        """Return a short fingerprint-like rendering for long identifiers (e.g., public keys)."""
        if not value:
            return "-"
        if len(value) <= keep * 2:
            return value
        return f"{value[:keep]}...{value[-keep:]}"

    def _render_contact_details(self, with_user: str, messages: list[dict]) -> None:
        """Populate the details pane (aliases, counts, last message timestamp, key preview)."""
        state = _state()
        contacts = self._load_contacts()
        aliases = [item["alias"] for item in contacts if item["username"] == with_user]
        alias_line = ", ".join(aliases) if aliases else "-"

        last_msg = messages[-1] if messages else {}
        last_time = last_msg.get("created_at", "-")
        msg_count = str(len(messages))

        public_key = "-"
        resp = _request(
            "GET",
            f"{_backend_url(state)}/api/users/{with_user}/public-key",
            token=(state.get("auth") or {}).get("token"),
        )
        if resp.status_code == 200:
            public_key = self._shorten(resp.json().get("public_key", "-"))
        elif resp.status_code == 404:
            self.query_one("#details", Static).update("User not found.")
            return

        details = (
            f"User: {with_user}\n"
            f"Aliases: {alias_line}\n"
            f"Messages: {msg_count}\n"
            f"Last: {last_time}\n"
            f"Public key: {public_key}"
        )
        self.query_one("#details", Static).update(details)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Select a contact and load the corresponding conversation."""
        if event.list_view.id != "contact-list":
            return
        user = getattr(event.item, "user", None)
        if not user:
            return
        self.current_with = user
        self._render_conversation(user)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Encrypt + send the composed message, then refresh the conversation view."""
        if event.input.id != "compose":
            return
        message = event.value.strip()
        if not message:
            return
        if not self.current_with:
            self._set_status("Select a conversation first.")
            return
        if self._send_payload(message):
            event.input.value = ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle on-screen buttons (keyboard shortcuts are handled by Textual actions)."""
        attachment_content = getattr(event.button, "attachment_content", None)
        if attachment_content is not None:
            self._save_attachment_from_content(attachment_content)
            return
        if event.button.id == "new-chat":
            self.action_new_chat()
            return
        if event.button.id == "refresh":
            self.action_refresh()
            return
        if event.button.id == "attach-file":
            self.action_attach_file()
            return
        if event.button.id == "admin-users":
            self.action_admin_users()
            return
        if event.button.id == "logout":
            self.action_logout()
            return

    @work(exclusive=True)
    async def action_new_chat(self) -> None:
        """Prompt for a user, validate they exist, add to contacts, and open the chat."""
        username = await self.app.push_screen(NewChatDialog(), wait_for_dismiss=True)
        if not username:
            return

        state = _state()
        auth = state.get("auth") or {}
        save_resp = _request(
            "POST",
            f"{_backend_url(state)}/api/contacts",
            token=auth.get("token"),
            json={"alias": username, "username": username},
        )
        if save_resp.status_code != 201:
            self._set_status(f"Failed to save contact: {save_resp.text}")
            return
        self._set_status(f"Added {username} to contacts.")
        self._refresh_contacts()

        list_view = self.query_one("#contact-list", ListView)
        for index, item in enumerate(list_view.children):
            if getattr(item, "user", None) == username:
                list_view.index = index
                break

        self.current_with = username
        self._render_conversation(username)

    def action_refresh(self) -> None:
        """Reload contacts and, if selected, re-fetch the active conversation."""
        self._refresh_contacts()
        if self.current_with:
            self._render_conversation(self.current_with)

    @work(exclusive=True)
    async def action_attach_file(self) -> None:
        """Prompt for a file path and send it immediately as an encrypted attachment envelope."""
        if not self.current_with:
            self._set_status("Select a conversation before attaching a file.")
            return

        path_value = await self.app.push_screen(AttachFileDialog(), wait_for_dismiss=True)
        if not path_value:
            return

        try:
            message, attachment_meta = _build_attachment_envelope(Path(path_value), "")
        except ValueError as exc:
            self._set_status(str(exc))
            return
        except OSError as exc:
            self._set_status(f"Failed to read attachment: {exc}")
            return
        if self._send_payload(message):
            self._set_status(f"Attachment sent: {attachment_meta['name']}.")

    @work(exclusive=True)
    async def action_admin_users(self) -> None:
        """Fetch and display the server-side user list for admin sessions."""
        if not self._can_view_admin_users():
            self._set_status("Admin access required.")
            return

        state = _state()
        auth = state.get("auth") or {}
        resp = _request(
            "GET",
            f"{_backend_url(state)}/api/admin/users",
            token=auth.get("token"),
        )
        if resp.status_code == 401:
            self._set_status("Session expired. Please login again.")
            self.app.push_screen(AuthScreen())
            return
        if resp.status_code == 403:
            self._set_status("Admin access denied by server.")
            return
        if resp.status_code != 200:
            self._set_status(f"Failed to load users: {resp.text}")
            return

        payload = resp.json()
        raw_users = payload.get("users", payload)
        usernames: list[str] = []
        if isinstance(raw_users, list):
            for entry in raw_users:
                if isinstance(entry, dict) and entry.get("username"):
                    usernames.append(str(entry["username"]))
                elif isinstance(entry, str):
                    usernames.append(entry)

        self._set_status(f"Loaded {len(usernames)} users.")
        await self.app.push_screen(UserListScreen(usernames), wait_for_dismiss=True)

    def action_logout(self) -> None:
        """Clear local auth state and return to the login screen."""
        state = _state()
        state["auth"] = {}
        _save_state(state)
        self.app.push_screen(AuthScreen())

    def _send_payload(self, message: str) -> bool:
        """Encrypt and send a text or attachment payload using the existing message API."""
        if not self.current_with:
            self._set_status("Select a conversation first.")
            return False

        state = _state()
        auth = state.get("auth") or {}
        recipient = _resolve_alias(state, self.current_with)

        pub_resp = _request(
            "GET",
            f"{_backend_url(state)}/api/users/{recipient}/public-key",
            token=auth.get("token"),
        )
        if pub_resp.status_code != 200:
            self._set_status(f"Failed to fetch public key: {pub_resp.text}")
            return False

        recipient_public_key = pub_resp.json()["public_key"]
        encrypted_key, ciphertext, iv = _encrypt_message(message, recipient_public_key)
        payload = {
            "recipient": recipient,
            "encrypted_key": encrypted_key,
            "ciphertext": ciphertext,
            "iv": iv,
        }
        post_resp = _request(
            "POST",
            f"{_backend_url(state)}/api/messages",
            token=auth.get("token"),
            json=payload,
        )
        if post_resp.status_code != 201:
            self._set_status(f"Send failed: {post_resp.text}")
            return False

        _append_history(
            {
                "id": post_resp.json().get("id"),
                "sender": auth.get("username"),
                "recipient": recipient,
                "plaintext": message,
            },
            save_history=state.get("save_history", True),
        )
        self._set_status(f"Sent message to {recipient}.")
        self._render_conversation(self.current_with)
        return True


class SecureMessageTUI(App):
    """Textual app entrypoint that selects Auth vs Message screen based on local auth TTL."""

    TITLE = "Secure Message"
    CSS = """
    Screen {
        layout: vertical;
    }
    """

    def on_mount(self) -> None:
        """Always start on the login screen rather than restoring a previous session."""
        self.push_screen(AuthScreen())


def run_tui() -> None:
    """CLI entrypoint for launching the Textual UI."""
    SecureMessageTUI().run()
