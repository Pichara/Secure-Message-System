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

TUI hotkeys:
- `n` new chat (adds user to Contacts if found)
- `r` refresh contacts
- `u` unlock inbox (decrypt received messages)
- `l` logout

![Secure Message CLI](../CLI.png)

## Register
```powershell
python secure_message_cli.py register alice
```
Password must be 8-128 characters and include at least one number and one special character.

## Login
```powershell
python secure_message_cli.py login alice
```
The CLI reads `/api/me` after login and stores the returned role in local state. Existing users can still log in with their current passwords.

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
Send an encrypted file attachment:
```powershell
python secure_message_cli.py send bob --file .\mockup.pdf --caption "latest mockup"
```
You can also use the positional message as the caption:
```powershell
python secure_message_cli.py send bob "latest mockup" --file .\mockup.pdf
```
Any file type can be attached. Attachment size is capped at 128 KiB on the CLI side.

## Read messages
```powershell
python secure_message_cli.py read bob
```
Attachment messages are shown as metadata in the conversation view, including message id, filename, mime type, size, and optional caption.

## Chat (thread view)
```powershell
python secure_message_cli.py chat bob
```

## Inbox (table)
```powershell
python secure_message_cli.py inbox --with bob
```

## Attachments
Show attachment metadata for a decrypted or locally saved attachment message:
```powershell
python secure_message_cli.py attachments show 42
```
Save an attachment to disk:
```powershell
python secure_message_cli.py attachments save 42 .\downloads
python secure_message_cli.py attachments save 42 .\downloads\mockup.pdf
```
Received attachments can always be decrypted from the server. Sent attachments can only be re-saved if local history storage was enabled when you sent them.

## Admin
List registered usernames for an admin session:
```powershell
python secure_message_cli.py admin users
```
`whoami` prints `username (admin)` for admin sessions.

## Contacts (aliases)
```powershell
python secure_message_cli.py contacts add boss alice
python secure_message_cli.py contacts list
python secure_message_cli.py contacts remove boss
```
Contacts are now stored on the backend per logged-in user, not in local machine state.

## Notes
- Private keys are encrypted locally with a password-derived key.
- Messages are encrypted end-to-end using X25519 + AES-GCM.
- File attachments are wrapped in an encrypted message envelope; the server still stores ciphertext only.
