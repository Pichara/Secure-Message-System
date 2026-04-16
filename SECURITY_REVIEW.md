# Security Review

Prepared by Rodrigo P Gomes. Frontend TypeScript review and fixes include Negin Karimi.

## Pentest Summary

This review focused on the exposed ASP.NET Core API, the React/TypeScript frontend, and the Python CLI test surface in this repository. The main findings that were fixed in code are:

1. `X-Forwarded-For` spoofing could weaken rate limiting because proxy headers were trusted unconditionally.
2. CORS allowed `*` by default, which is too permissive for a browser client.
3. The backend returned only minimal hardening headers and had no CSP, frame, or referrer restrictions.
4. Sensitive auth/admin events were not logged, leaving monitoring and forensic gaps.
5. The frontend gated `/admin` only by “logged in” state; it now restores role from `/api/me` and blocks non-admin navigation.
6. Browser bearer tokens were kept in `localStorage`; they are now migrated to `sessionStorage` to reduce persistence and XSS blast radius.

## SQL Injection Check: TUI Inputs and Attachments

The Python TUI and CLI do not build SQL locally. They send JSON payloads to the backend API using `requests`, including usernames, aliases, passwords, message bodies, and attachment envelopes.

The attachment flow is not a classic multipart upload path. The client reads the file locally, wraps it into a JSON envelope, encrypts it client-side, and sends only the encrypted payload through `POST /api/messages`.

For the backend storage path, repository methods use parameterized `NpgsqlCommand` statements with placeholders such as `$1`, `$2`, and `$3`. That means TUI input values and attachment metadata are treated as data, not executable SQL.

Result: no SQL injection path was identified from TUI inputs or the encrypted attachment upload flow in the current implementation.

## OWASP Top 10 Coverage

| Category | Repository evidence |
| --- | --- |
| A01 Broken Access Control | Per-user message filtering, admin-only endpoints, frontend admin role guard restoration |
| A02 Cryptographic Failures | E2EE, AES-GCM, Argon2id, PBKDF2-protected private key storage |
| A03 Injection | Parameterized Npgsql queries throughout repositories; no SQL construction from TUI inputs or attachment metadata |
| A05 Security Misconfiguration | Hardened CORS defaults, security headers, optional HSTS |
| A07 Identification and Authentication Failures | Password policy, token invalidation, rate limiting, reduced token persistence |
| A09 Security Logging and Monitoring Failures | Added logging for failed login, blocked admin access, rate-limit events, admin deletion |

## STRIDE Table

| Threat | Entry point | Risk description | Mitigation |
| --- | --- | --- | --- |
| S Spoofing | `Authorization` bearer token, proxy headers | Stolen tokens or spoofed proxy IPs can impersonate users or bypass coarse IP throttles | Short TTL tokens, logout invalidation, session storage migration, proxy headers disabled unless explicitly trusted |
| T Tampering | `POST /api/messages`, `POST /api/contacts`, frontend local state | Attackers can try to alter ciphertext, attachment envelopes, aliases, or request bodies | AES-GCM authenticated encryption, bounded field validation, body-size enforcement, server-side auth checks |
| R Repudiation | Login, logout, admin deletion, rate-limited endpoints | Without audit trails, abusive or privileged actions are hard to attribute | Added structured logging for failed auth, rate-limit hits, forbidden admin access, and account deletion |
| I Information Disclosure | `/api/me`, `/api/admin/users`, browser storage, CORS | Excessive data exposure or persistent token storage can leak account or session data | Admin endpoints return usernames only, CORS defaults restricted, tokens moved to session storage, no-store headers |
| D Denial of Service | Auth endpoints, large POST bodies, polling | Brute force and oversized requests can exhaust CPU, memory, or DB resources | Rate limiting, body-size limits, field length validation, capped pagination |
| E Elevation of Privilege | `/api/admin/*`, frontend `/admin` route | Non-admins may try to reach privileged actions or UI flows | Backend role enforcement, frontend admin route guard restored from server role, delete restrictions on admin/self |

## Remaining Risks

1. Tokens are still opaque in-memory bearer tokens, not signed JWTs or HttpOnly cookies. That is acceptable for coursework/demo scope but not ideal for production.
2. Request body enforcement still depends on middleware and configured max lengths rather than streaming upload controls.
3. There is no dedicated backend unit/integration test project yet; current verification relies on CLI-driven API and E2E tests.
