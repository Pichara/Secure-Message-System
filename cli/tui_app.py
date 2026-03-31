from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from textual.app import App, ComposeResult
from textual import work
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, Header, Input, ListItem, ListView, RichLog, Static

from secure_message_cli import (
    _append_history,
    _auth_valid,
    _backend_url,
    _decrypt_message,
    _encrypt_message,
    _encrypt_private_key,
    _generate_keypair,
    _load_history,
    _load_private_key_from_state,
    _request,
    _resolve_alias,
    _serialize_private_key,
    _serialize_public_key,
    _state,
    _save_state,
)


@dataclass
class AuthState:
    token: str
    username: str


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
        state["auth"] = {
            "token": token,
            "username": username,
            "expires_at": expires_at.isoformat(),
        }
        state["keys"] = {
            "public_key": me["public_key"],
            "encrypted_private_key": me["encrypted_private_key"],
        }
        _save_state(state)
        return AuthState(token=token, username=username)

    def _register(self, username: str, password: str, confirm: str) -> bool:
        """Register a user by generating a keypair and uploading only public + encrypted private key."""
        if password != confirm:
            self._set_status("Password confirmation does not match.")
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
                    message = data.get("message") or "Password must be 8-128 characters."
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
            self.app.push_screen(MessageScreen(auth))


class MessageScreen(Screen):
    """Main messaging UI: contacts on the left, conversation + compose on the right."""

    BINDINGS = [
        ("n", "new_chat", "New chat"),
        ("r", "refresh", "Refresh"),
        ("u", "unlock", "Unlock inbox"),
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
    #messages {
        width: 70%;
        border: round #4c4c4c;
    }
    #compose {
        height: 3;
        border: round #4c4c4c;
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
        self.private_key = None
        self.current_with: Optional[str] = None

    def compose(self) -> ComposeResult:
        """Render sidebar contact list, message log, and compose box."""
        yield Header()
        with Horizontal(id="main"):
            with Container(id="sidebar"):
                yield Static("Contacts", id="sidebar-title")
                yield ListView(id="contact-list")
                yield Static("No contact selected.", id="details")
            with Vertical(id="messages"):
                yield RichLog(id="message-log", wrap=True)
                yield Input(placeholder="Type message and press Enter", id="compose")
        yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        """Disable compose until a conversation is loaded; then render contacts."""
        self.query_one("#compose", Input).disabled = True
        self._refresh_contacts()

    def _set_status(self, message: str) -> None:
        """Update the transient status line at the bottom of the screen."""
        self.query_one("#status", Static).update(message)

    def _refresh_contacts(self) -> None:
        """Re-render the sidebar contact list from local state (no backend call)."""
        state = _state()
        auth = state.get("auth") or {}
        if not _auth_valid(auth):
            self.app.push_screen(AuthScreen())
            return

        contacts = state.get("contacts") or {}
        list_view = self.query_one("#contact-list", ListView)
        list_view.clear()

        for alias, username in sorted(contacts.items()):
            label = f"{alias} ({username})" if alias != username else username
            item = ListItem(Static(label))
            item.user = username
            item.alias = alias
            list_view.append(item)

        if not contacts:
            self._set_status("No contacts yet. Press 'n' to add one.")

    def _render_conversation(self, with_user: str) -> None:
        """Fetch messages with `with_user` and render decrypted/plaintext view when possible."""
        state = _state()
        auth = state.get("auth") or {}
        history = _load_history()

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
            return

        messages = resp.json()
        messages.sort(key=lambda msg: msg.get("created_at", ""))
        log = self.query_one("#message-log", RichLog)
        log.clear()
        if not messages:
            log.write("No messages yet. Send one below.")
        for msg in messages:
            sender = msg.get("sender", "unknown")
            recipient = msg.get("recipient", "unknown")
            created_at = msg.get("created_at", "unknown")
            if recipient == auth.get("username"):
                if self.private_key is None:
                    # Inbox remains locked until the user decrypts their private key locally.
                    plaintext = "[inbox locked]"
                else:
                    try:
                        plaintext = _decrypt_message(
                            msg.get("ciphertext", ""),
                            msg.get("iv", ""),
                            msg.get("encrypted_key", ""),
                            self.private_key,
                        )
                    except Exception:
                        plaintext = "[decryption failed]"
            else:
                # Sent-message plaintext is only stored locally (optional); server stores ciphertext only.
                plaintext = history.get(str(msg.get("id")), "[sent message not stored locally]")
            log.write(f"{created_at} {sender} -> {recipient}: {plaintext}")

        self.query_one("#compose", Input).disabled = False
        self.query_one("#compose", Input).focus()
        self._render_contact_details(with_user, messages)
        self._set_status(f"Chatting with {with_user}")

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
        contacts = state.get("contacts") or {}
        aliases = [alias for alias, username in contacts.items() if username == with_user]
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

        state = _state()
        auth = state.get("auth") or {}
        recipient = _resolve_alias(state, self.current_with)

        # We encrypt to the recipient's public key (E2EE); the server only ever receives ciphertext.
        pub_resp = _request(
            "GET",
            f"{_backend_url(state)}/api/users/{recipient}/public-key",
            token=auth.get("token"),
        )
        if pub_resp.status_code != 200:
            self._set_status(f"Failed to fetch public key: {pub_resp.text}")
            return

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
            return

        save_history = state.get("save_history", True)
        # Store sent plaintext locally (optional) so the UI can display outbound messages without decrypting.
        _append_history(
            {
                "id": post_resp.json().get("id"),
                "sender": auth.get("username"),
                "recipient": recipient,
                "plaintext": message,
            },
            save_history=save_history,
        )
        event.input.value = ""
        self._render_conversation(self.current_with)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle on-screen buttons (keyboard shortcuts are handled by Textual actions)."""
        if event.button.id == "new-chat":
            await self.action_new_chat()
            return
        if event.button.id == "refresh":
            self.action_refresh()
            return

    @work(exclusive=True)
    async def action_new_chat(self) -> None:
        """Prompt for a user, validate they exist, add to contacts, and open the chat."""
        while True:
            username = await self.app.push_screen(InputDialog("Start chat with:", "username"), wait_for_dismiss=True)
            if not username:
                return
            state = _state()
            username = _resolve_alias(state, username)
            auth = state.get("auth") or {}

            # Existence check: /public-key doubles as a "does this user exist" lookup.
            resp = _request(
                "GET",
                f"{_backend_url(state)}/api/users/{username}/public-key",
                token=auth.get("token"),
            )
            if resp.status_code != 200:
                if resp.status_code == 401:
                    self._set_status("Session expired. Please login again.")
                    self.app.push_screen(AuthScreen())
                    return
                if resp.status_code == 404:
                    self._set_status("User not found.")
                    continue
                self._set_status(f"Failed to resolve user: {resp.text}")
                return

            contacts = state.get("contacts") or {}
            if username not in contacts.values() and username not in contacts.keys():
                contacts[username] = username
                state["contacts"] = contacts
                _save_state(state)
                self._set_status(f"Added {username} to contacts.")
            else:
                self._set_status(f"{username} is already in contacts.")
            self._refresh_contacts()

            list_view = self.query_one("#contact-list", ListView)
            for index, item in enumerate(list_view.children):
                if getattr(item, "user", None) == username:
                    list_view.index = index
                    break

            self.current_with = username
            self._render_conversation(username)
            return

    def action_refresh(self) -> None:
        """Reload contacts and, if selected, re-fetch the active conversation."""
        self._refresh_contacts()
        if self.current_with:
            self._render_conversation(self.current_with)

    @work(exclusive=True)
    async def action_unlock(self) -> None:
        """Decrypt the private key into memory so inbound messages can be decrypted in the UI."""
        password = await self.app.push_screen(
            InputDialog("Unlock inbox", "password", password=True),
            wait_for_dismiss=True,
        )
        if not password:
            return
        state = _state()
        try:
            # Decrypted private key is intentionally kept in-memory only for this session/screen.
            self.private_key = _load_private_key_from_state(state, password)
            self._set_status("Inbox unlocked.")
            if self.current_with:
                self._render_conversation(self.current_with)
        except Exception:
            self._set_status("Failed to decrypt private key.")

    def action_logout(self) -> None:
        """Clear local auth state and return to the login screen."""
        state = _state()
        state["auth"] = {}
        _save_state(state)
        self.app.push_screen(AuthScreen())


class SecureMessageTUI(App):
    """Textual app entrypoint that selects Auth vs Message screen based on local auth TTL."""

    TITLE = "Secure Message"
    CSS = """
    Screen {
        layout: vertical;
    }
    """

    def on_mount(self) -> None:
        """Boot into the message view if an existing token is still valid; otherwise show auth."""
        state = _state()
        auth = state.get("auth") or {}
        if _auth_valid(auth):
            self.push_screen(MessageScreen(AuthState(token=auth["token"], username=auth["username"])))
        else:
            self.push_screen(AuthScreen())


def run_tui() -> None:
    """CLI entrypoint for launching the Textual UI."""
    SecureMessageTUI().run()
