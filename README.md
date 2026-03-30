# Secure Message System (Overview)

Academic secure messaging project with **end-to-end encryption (E2EE)** and explicit **OWASP Top 10** alignment.

## Core Concepts (Concise)
1. **E2EE by design**: messages are encrypted client‑side (AES‑GCM); the server stores only ciphertext.
2. **Key management**: clients generate key pairs; private keys are encrypted with a password‑derived key.
3. **Zero‑knowledge backend**: the server cannot decrypt message content.
4. **Defense in depth**: strong auth, strict authorization, input validation, and secure error handling.

## OWASP Top 10 Mapping (Summary)
1. **Broken Access Control**: server enforces per‑user message access.
2. **Cryptographic Failures**: E2EE, strong KDF, AES‑GCM integrity.
3. **Injection**: parameterized SQL queries.
4. **Insecure Design**: threat model + data flow documented.
5. **Security Misconfiguration**: secure headers and safe defaults.
6. **Vulnerable Components**: minimal dependencies, pinned versions.
7. **Identification & Auth Failures**: hashed passwords, session controls.
8. **Integrity Failures**: authenticated encryption + TLS.
9. **Logging & Monitoring**: audit logs for auth and message events.
10. **SSRF/XSS/CSRF**: input/output controls, CSRF protection for state changes.

## Architecture (High Level)
- **Clients (Web/CLI)** → **Backend API** → **PostgreSQL**
- API handles auth, public key lookup, and message storage (ciphertext only).

## API (Current)
1. `GET /health`
2. `POST /api/register`
3. `POST /api/login`
4. `POST /api/logout`
5. `GET /api/me`
6. `GET /api/users/{username}/public-key`
7. `POST /api/messages`
8. `GET /api/messages`
   - Optional query params: `with`, `limit`, `order` (`asc|desc`), `before_id`

## API Notes
- CORS defaults to `*` and can be overridden with `CORS_ORIGIN`.
- Responses are JSON; errors use `{"error":"..."}`.

## Stack (Reference)
- Backend: C++ (cpp‑httplib, nlohmann/json, libpqxx, libsodium)
- DB: PostgreSQL
- CLI: Python (Typer, Requests, Cryptography)
