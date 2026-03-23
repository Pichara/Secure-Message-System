# Secure Message CLI

## Install
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
```
If you already installed packages globally, re-run `pip install -r requirements.txt` to pin `click==8.1.7` (fixes help display errors with newer Click versions).

## Configure backend
```powershell
python secure_message_cli.py config set-url http://localhost:8080
```

## Register
```powershell
python secure_message_cli.py register alice
```

## Login
```powershell
python secure_message_cli.py login alice
```

## Send message
```powershell
python secure_message_cli.py send bob "hello from cli"
```

## Read messages
```powershell
python secure_message_cli.py read bob
```

## Inbox (raw)
```powershell
python secure_message_cli.py inbox --with bob
```

## Notes
- Private keys are encrypted locally with a password-derived key.
- Messages are encrypted end-to-end using X25519 + AES-GCM.
