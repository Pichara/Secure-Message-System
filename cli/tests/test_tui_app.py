import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

import tui_app
from textual.widgets import Button
from tui_app import AdminDirectoryScreen, AttachFileDialog, AuthState, ConfirmDialog, MessageScreen, NewChatDialog, SecureMessageTUI


class _FakeResponse:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


def test_new_chat_dialog_keeps_modal_open_for_missing_user(monkeypatch):
    async def scenario():
        app = SecureMessageTUI()
        dialog = NewChatDialog()

        monkeypatch.setattr(
            tui_app,
            "_state",
            lambda: {"auth": {"token": "test-token"}, "backend_url": "http://localhost:8080"},
        )
        monkeypatch.setattr(tui_app, "_backend_url", lambda state: "http://localhost:8080")
        monkeypatch.setattr(tui_app, "_resolve_alias", lambda state, username: username)

        def fake_request(method: str, url: str, token=None, **kwargs):
            assert method == "GET"
            assert url.endswith("/api/users/ghost/public-key")
            assert token == "test-token"
            return _FakeResponse(404, {"error": "user_not_found"}, "user_not_found")

        monkeypatch.setattr(tui_app, "_request", fake_request)

        async with app.run_test() as pilot:
            app.push_screen(dialog)
            await pilot.pause()
            dialog.query_one("#new-chat-input").value = "ghost"
            dialog._submit()
            await pilot.pause()
            assert str(dialog.query_one("#new-chat-status").renderable) == "User not found!"
            assert dialog.query_one("#new-chat-input").value == "ghost"

    asyncio.run(scenario())


def test_auto_refresh_updates_open_conversation_when_new_message_arrives(monkeypatch):
    async def scenario():
        app = SecureMessageTUI()
        screen = MessageScreen(AuthState(token="test-token", username="alice", private_key=None))

        states = [
            [
                {
                    "id": 1,
                    "sender": "alice",
                    "recipient": "bob",
                    "ciphertext": "c1",
                    "iv": "iv1",
                    "encrypted_key": "k1",
                    "created_at": "2026-04-15T20:00:00Z",
                }
            ],
            [
                {
                    "id": 1,
                    "sender": "alice",
                    "recipient": "bob",
                    "ciphertext": "c1",
                    "iv": "iv1",
                    "encrypted_key": "k1",
                    "created_at": "2026-04-15T20:00:00Z",
                },
                {
                    "id": 2,
                    "sender": "bob",
                    "recipient": "alice",
                    "ciphertext": "c2",
                    "iv": "iv2",
                    "encrypted_key": "k2",
                    "created_at": "2026-04-15T20:01:00Z",
                },
            ],
        ]
        index = {"value": 0}

        monkeypatch.setattr(
            tui_app,
            "_state",
            lambda: {"auth": {"token": "test-token", "username": "alice"}, "backend_url": "http://localhost:8080"},
        )
        monkeypatch.setattr(tui_app, "_backend_url", lambda state: "http://localhost:8080")
        monkeypatch.setattr(tui_app, "_load_history", lambda: [])
        monkeypatch.setattr(tui_app, "_history_display", lambda history, message_id: f"history-{message_id}")
        monkeypatch.setattr(tui_app, "_format_message_log_line", lambda created_at, sender, recipient, plaintext: f"{sender}->{recipient}:{plaintext}")

        def fake_request(method: str, url: str, token=None, **kwargs):
            assert token == "test-token"
            if method == "GET" and url.endswith("/api/contacts"):
                return _FakeResponse(200, [{"alias": "bob", "username": "bob"}])
            if method == "GET" and url.endswith("/api/users/bob/public-key"):
                return _FakeResponse(200, {"public_key": "public-key"})
            if method == "GET" and "/api/messages?with=bob" in url:
                return _FakeResponse(200, states[index["value"]])
            raise AssertionError(f"Unexpected request: {method} {url}")

        monkeypatch.setattr(tui_app, "_request", fake_request)

        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()
            screen.current_with = "bob"
            screen._render_conversation("bob")
            await pilot.pause()

            index["value"] = 1
            screen._auto_refresh_active_chat()
            await pilot.pause()

            log_children = list(screen.query_one("#message-log").children)
            assert len(log_children) == 2
            assert "alice->bob" in str(log_children[0].label if isinstance(log_children[0], Button) else log_children[0].renderable)
            assert "bob->alice" in str(log_children[1].label if isinstance(log_children[1], Button) else log_children[1].renderable)
            assert str(screen.query_one("#status").renderable) == "New messages in chat with bob."

    asyncio.run(scenario())


def test_attachment_messages_render_clickable_and_save_on_click(monkeypatch):
    async def scenario():
        app = SecureMessageTUI()
        screen = MessageScreen(AuthState(token="test-token", username="alice", private_key=None))

        with TemporaryDirectory() as tmp_dir:
            monkeypatch.setattr(tui_app.Path, "home", staticmethod(lambda: Path(tmp_dir)))
            monkeypatch.setattr(
                tui_app,
                "_state",
                lambda: {"auth": {"token": "test-token", "username": "alice"}, "backend_url": "http://localhost:8080"},
            )
            monkeypatch.setattr(tui_app, "_backend_url", lambda state: "http://localhost:8080")
            monkeypatch.setattr(tui_app, "_load_history", lambda: [])
            monkeypatch.setattr(tui_app, "_format_message_log_line", lambda created_at, sender, recipient, plaintext: plaintext)
            monkeypatch.setattr(
                tui_app,
                "_decrypt_message",
                lambda ciphertext, iv, encrypted_key, private_key, username=None: '{"kind":"attachment","caption":"","attachment":{"name":"proof.bin","mime":"application/octet-stream","size_bytes":7,"bytes_b64":"cGF5bG9hZA=="}}',
            )

            def fake_request(method: str, url: str, token=None, **kwargs):
                assert token == "test-token"
                if method == "GET" and url.endswith("/api/contacts"):
                    return _FakeResponse(200, [{"alias": "bob", "username": "bob"}])
                if method == "GET" and url.endswith("/api/users/bob/public-key"):
                    return _FakeResponse(200, {"public_key": "public-key"})
                if method == "GET" and "/api/messages?with=bob" in url:
                    return _FakeResponse(
                        200,
                        [
                            {
                                "id": 9,
                                "sender": "bob",
                                "recipient": "alice",
                                "ciphertext": "c",
                                "iv": "iv",
                                "encrypted_key": "k",
                                "created_at": "2026-04-15T20:01:00Z",
                            }
                        ],
                    )
                raise AssertionError(f"Unexpected request: {method} {url}")

            monkeypatch.setattr(tui_app, "_request", fake_request)
            screen.private_key = object()

            async with app.run_test() as pilot:
                app.push_screen(screen)
                await pilot.pause()
                screen.current_with = "bob"
                screen._render_conversation("bob")
                await pilot.pause()

                attachment_button = screen.query_one("#attachment-msg-9", Button)
                screen.on_button_pressed(type("AttachmentEvent", (), {"button": attachment_button})())
                await pilot.pause()

                saved_path = Path(tmp_dir) / "Downloads" / "proof.bin"
                assert saved_path.exists()
                assert saved_path.read_bytes() == b"payload"
                assert "Attachment saved to" in str(screen.query_one("#status").renderable)

    asyncio.run(scenario())


def test_attach_file_dialog_keeps_modal_open_for_missing_path():
    async def scenario():
        app = SecureMessageTUI()
        dialog = AttachFileDialog()

        async with app.run_test() as pilot:
            app.push_screen(dialog)
            await pilot.pause()
            dialog.query_one("#attach-file-input").value = r"C:\missing-file.bin"
            dialog._submit()
            await pilot.pause()
            assert str(dialog.query_one("#attach-file-status").renderable) == "File not found."
            assert dialog.query_one("#attach-file-input").value == r"C:\missing-file.bin"

    asyncio.run(scenario())


def test_attach_file_sends_immediately_without_caption(monkeypatch):
    async def scenario():
        app = SecureMessageTUI()
        screen = MessageScreen(AuthState(token="test-token", username="alice"))

        with TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "evidence.bin"
            file_path.write_bytes(b"payload")

            monkeypatch.setattr(tui_app, "_build_attachment_envelope", lambda path, caption: ("encrypted-payload", {"name": path.name, "caption": caption}))

            async def fake_push_screen(screen_obj, wait_for_dismiss=False):
                if isinstance(screen_obj, AttachFileDialog):
                    return str(file_path)
                return None

            sent_payloads: list[str] = []

            def fake_send_payload(message: str) -> bool:
                sent_payloads.append(message)
                return True

            screen.current_with = "bob"

            async with app.run_test() as pilot:
                app.push_screen(screen)
                await pilot.pause()
                monkeypatch.setattr(app, "push_screen", fake_push_screen)
                monkeypatch.setattr(screen, "_send_payload", fake_send_payload)
                worker = screen.action_attach_file()
                await worker.wait()
                await pilot.pause()
                assert sent_payloads == ["encrypted-payload"]
                assert str(screen.query_one("#status").renderable) == "Attachment sent: evidence.bin."

    asyncio.run(scenario())


def test_admin_directory_renders_selectable_users_and_enables_delete(monkeypatch):
    async def scenario():
        app = SecureMessageTUI()
        screen = AdminDirectoryScreen(AuthState(token="test-token", username="ADMIN", role="admin"))

        monkeypatch.setattr(
            tui_app,
            "_state",
            lambda: {"auth": {"token": "test-token", "username": "ADMIN", "role": "admin"}, "backend_url": "http://localhost:8080"},
        )
        monkeypatch.setattr(tui_app, "_backend_url", lambda state: "http://localhost:8080")

        def fake_request(method: str, url: str, token=None, **kwargs):
            assert token == "test-token"
            if method == "GET" and url.endswith("/api/admin/users"):
                return _FakeResponse(200, {"users": [{"username": "ADMIN"}, {"username": "alice"}]})
            raise AssertionError(f"Unexpected request: {method} {url}")

        monkeypatch.setattr(tui_app, "_request", fake_request)

        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()

            list_view = screen.query_one("#admin-user-list")
            delete_button = screen.query_one("#delete", Button)

            assert len(list_view.children) == 2
            assert screen._selected_username == "ADMIN"
            assert delete_button.disabled is False

    asyncio.run(scenario())


def test_admin_directory_delete_user_confirms_then_refreshes(monkeypatch):
    async def scenario():
        app = SecureMessageTUI()
        screen = AdminDirectoryScreen(AuthState(token="test-token", username="ADMIN", role="admin"))
        requests: list[tuple[str, str]] = []
        refresh_round = {"value": 0}

        monkeypatch.setattr(
            tui_app,
            "_state",
            lambda: {"auth": {"token": "test-token", "username": "ADMIN", "role": "admin"}, "backend_url": "http://localhost:8080"},
        )
        monkeypatch.setattr(tui_app, "_backend_url", lambda state: "http://localhost:8080")

        def fake_request(method: str, url: str, token=None, **kwargs):
            assert token == "test-token"
            requests.append((method, url))
            if method == "GET" and url.endswith("/api/admin/users"):
                if refresh_round["value"] == 0:
                    refresh_round["value"] = 1
                    return _FakeResponse(200, {"users": [{"username": "ADMIN"}, {"username": "alice"}]})
                return _FakeResponse(200, {"users": [{"username": "ADMIN"}]})
            if method == "DELETE" and url.endswith("/api/admin/users/alice"):
                return _FakeResponse(200, {"status": "deleted"})
            raise AssertionError(f"Unexpected request: {method} {url}")

        async def fake_push_screen(screen_obj, wait_for_dismiss=False):
            if isinstance(screen_obj, ConfirmDialog):
                return True
            return None

        monkeypatch.setattr(tui_app, "_request", fake_request)

        async with app.run_test() as pilot:
            app.push_screen(screen)
            await pilot.pause()
            monkeypatch.setattr(app, "push_screen", fake_push_screen)

            screen._selected_username = "alice"
            screen._sync_delete_button()
            worker = screen.action_delete_user()
            await worker.wait()
            await pilot.pause()

            usernames = [getattr(item, "username", None) for item in screen.query_one("#admin-user-list").children]
            assert ("DELETE", "http://localhost:8080/api/admin/users/alice") in requests
            assert usernames == ["ADMIN"]
            assert str(screen.query_one("#admin-status").renderable) == "Loaded 1 users."

    asyncio.run(scenario())
