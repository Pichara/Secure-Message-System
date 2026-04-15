# Secure Message Backend (C++)

## Overview
Minimal C++ backend API for the secure messaging project. This is a **starter scaffold** backed by **PostgreSQL**.

## Requirements
- CMake 3.20+
- C++17 compiler
- PostgreSQL client libraries (`libpq`, `libpqxx`)
- libsodium
- Git (FetchContent pulls header-only dependencies)

## Environment Variables
- `DATABASE_URL` (required)
  - Example: `postgresql://postgres:postgres@localhost:5432/secure_message`
- `PORT` (optional, default `8080`)

## Build (local)
```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Run (local)
```powershell
$env:DATABASE_URL="postgresql://postgres:postgres@localhost:5432/secure_message"
./build/secure_message_backend
```

## Docker
```powershell
docker build -t secure-message-backend .
docker run -p 8080:8080 -e DATABASE_URL="postgresql://postgres:postgres@host.docker.internal:5432/secure_message" secure-message-backend
```

## Docker Compose (recommended)
From the project root:
```powershell
docker compose up --build
```
This starts PostgreSQL and the backend with the correct `DATABASE_URL`.

## API (current)
- `GET /health`
- `POST /api/register`
- `POST /api/login`
- `POST /api/logout`
- `GET /api/me`
- `GET /api/admin/users`
- `GET /api/users/{username}/public-key`
- `POST /api/messages`
- `GET /api/messages?with={username}`

## Security Notes (OWASP)
- Passwords are hashed with **Argon2id** via libsodium.
- New registrations require passwords that are 8-128 characters long and include at least one number and one special character.
- Queries are parameterized to prevent SQL injection.
- Tokens are short-lived (1 hour) and stored in memory (demo).
- E2EE message content is stored as ciphertext only.
- Admin access uses the normal login flow. User records default to `role=user`, `/api/me` returns that role, and `/api/admin/users` is restricted to admin accounts.
- Existing databases are migrated on startup to add the `role` column automatically.
- Message storage remains opaque. The backend now accepts larger encrypted payloads so clients can send small attachment/image envelopes through the existing encrypted message pipeline.
