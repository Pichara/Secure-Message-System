# Secure Message CLI

## Install
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```
If you already installed packages globally, re-run `pip install -r requirements.txt` to pin `click==8.1.7` (fixes help display errors with newer Click versions).
`prompt_toolkit` is used for the single-key menu in the launcher/session shells.

## Configure backend
```powershell
python secure_message_cli.py config set-url http://localhost:8080
```
Show config (masked by default):
```powershell
python secure_message_cli.py config show
python secure_message_cli.py config show --full
```
Disable local history storage:
```powershell
python secure_message_cli.py config set-history off
```

## Launcher (default)
```powershell
python secure_message_cli.py
```
This opens the full-screen TUI by default. Use arrow keys and Enter to navigate.

Open the TUI explicitly:
```powershell
python secure_message_cli.py tui
```

Open the legacy menu launcher:
```powershell
python secure_message_cli.py launcher
```

## Register
```powershell
python secure_message_cli.py register alice
```

## Login
```powershell
python secure_message_cli.py login alice
```

## Shell (menu)
```powershell
python secure_message_cli.py shell
```
Menu options (requires login):
1. Send message
2. View messages
3. Chat
4. Exit

## Send message
```powershell
python secure_message_cli.py send bob "hello from cli"
```
Send without saving plaintext locally:
```powershell
python secure_message_cli.py send bob "hello" --no-history
```

## Read messages
```powershell
python secure_message_cli.py read bob
```

## Chat (thread view)
```powershell
python secure_message_cli.py chat bob
```

## Inbox (table)
```powershell
python secure_message_cli.py inbox --with bob
```

## Contacts (aliases)
```powershell
python secure_message_cli.py contacts add boss alice
python secure_message_cli.py contacts list
python secure_message_cli.py contacts remove boss
```

## Notes
- Private keys are encrypted locally with a password-derived key.
- Messages are encrypted end-to-end using X25519 + AES-GCM.
