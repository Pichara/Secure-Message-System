#include <httplib.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <sodium.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using json = nlohmann::json;

struct TokenInfo {
  std::string username;
  std::chrono::system_clock::time_point expires_at;
};

struct DbUser {
  int id = 0;
  std::string username;
  std::string password_hash;
  std::string public_key;
  std::string encrypted_private_key;
};

constexpr size_t kMaxBodyBytes = 256 * 1024;
constexpr size_t kMinUsernameLen = 3;
constexpr size_t kMaxUsernameLen = 32;
constexpr size_t kMinPasswordLen = 8;
constexpr size_t kMaxPasswordLen = 128;
constexpr size_t kMaxPublicKeyLen = 512;
constexpr size_t kMaxEncryptedPrivateKeyLen = 8192;
constexpr size_t kMaxEncryptedKeyLen = 4096;
constexpr size_t kMaxCiphertextLen = 16384;
constexpr size_t kMaxIvLen = 128;

struct RateLimitEntry {
  int count = 0;
  std::chrono::system_clock::time_point window_start{};
};

struct RateLimiter {
  bool Allow(const std::string& key,
             int limit,
             std::chrono::seconds window,
             std::chrono::system_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mu);
    auto& entry = entries[key];
    if (entry.count == 0 || now - entry.window_start > window) {
      entry.count = 0;
      entry.window_start = now;
    }
    entry.count += 1;
    return entry.count <= limit;
  }

  std::mutex mu;
  std::unordered_map<std::string, RateLimitEntry> entries;
};

struct CorsConfig {
  bool allow_all = true;
  std::unordered_set<std::string> allowed;
};

// Format the current UTC time as an ISO-8601 string for logs/metadata.
std::string NowIso8601Utc() {
  using namespace std::chrono;
  auto now = system_clock::now();
  auto tt = system_clock::to_time_t(now);
  std::tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &tt);
#else
  gmtime_r(&tt, &tm_utc);
#endif
  std::ostringstream oss;
  oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// Read an environment variable with a safe fallback.
std::string GetEnvOrDefault(const char* key, const char* fallback) {
  const char* value = std::getenv(key);
  if (value && *value) {
    return std::string(value);
  }
  return std::string(fallback);
}

// Trim ASCII whitespace from both ends of a string.
std::string Trim(const std::string& input) {
  size_t start = 0;
  while (start < input.size() &&
         std::isspace(static_cast<unsigned char>(input[start]))) {
    start++;
  }
  size_t end = input.size();
  while (end > start &&
         std::isspace(static_cast<unsigned char>(input[end - 1]))) {
    end--;
  }
  return input.substr(start, end - start);
}

// Parse a comma-separated list into a set of trimmed values.
std::unordered_set<std::string> SplitCsvToSet(const std::string& csv) {
  std::unordered_set<std::string> result;
  std::stringstream ss(csv);
  std::string item;
  while (std::getline(ss, item, ',')) {
    auto trimmed = Trim(item);
    if (!trimmed.empty()) {
      result.insert(trimmed);
    }
  }
  return result;
}

// Interpret common truthy strings (1/true/yes), case-insensitive.
bool IsTruthy(const std::string& value) {
  std::string v;
  v.reserve(value.size());
  for (char ch : value) {
    v.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return v == "1" || v == "true" || v == "yes";
}

// Build the database connection URL from env.
std::string GetDbUrl() {
  return GetEnvOrDefault("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/secure_message");
}

// Generate a random 256-bit token encoded as hex.
std::string GenerateToken() {
  std::array<unsigned char, 32> bytes{};
  randombytes_buf(bytes.data(), bytes.size());
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (unsigned char b : bytes) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0f]);
  }
  return out;
}

// Pull "Authorization: Bearer <token>" from a request if present.
std::optional<std::string> ExtractBearerToken(const httplib::Request& req) {
  auto auth = req.get_header_value("Authorization");
  const std::string prefix = "Bearer ";
  if (auth.rfind(prefix, 0) != 0) {
    return std::nullopt;
  }
  return auth.substr(prefix.size());
}

// Validate bearer token and return associated username when active.
std::optional<std::string> ValidateToken(const httplib::Request& req,
                                         std::unordered_map<std::string, TokenInfo>& tokens,
                                         std::mutex& token_mu,
                                         std::chrono::system_clock::time_point& last_cleanup) {
  auto token_opt = ExtractBearerToken(req);
  if (!token_opt.has_value()) {
    return std::nullopt;
  }
  std::string token = *token_opt;
  auto now = std::chrono::system_clock::now();

  std::lock_guard<std::mutex> lock(token_mu);
  // Periodically sweep expired tokens to bound memory usage.
  if (now - last_cleanup > std::chrono::minutes(5)) {
    for (auto it = tokens.begin(); it != tokens.end();) {
      if (it->second.expires_at < now) {
        it = tokens.erase(it);
      } else {
        ++it;
      }
    }
    last_cleanup = now;
  }
  auto it = tokens.find(token);
  if (it == tokens.end()) {
    return std::nullopt;
  }
  if (it->second.expires_at < now) {
    tokens.erase(it);
    return std::nullopt;
  }
  return it->second.username;
}

// Validate usernames with a small safe character set.
bool IsValidUsername(const std::string& username) {
  if (username.size() < kMinUsernameLen || username.size() > kMaxUsernameLen) {
    return false;
  }
  for (char ch : username) {
    if (std::isalnum(static_cast<unsigned char>(ch))) {
      continue;
    }
    if (ch == '_' || ch == '-' || ch == '.') {
      continue;
    }
    return false;
  }
  return true;
}

// Enforce basic length policy; complexity rules are client-side.
bool IsValidPassword(const std::string& password) {
  return password.size() >= kMinPasswordLen && password.size() <= kMaxPasswordLen;
}

// Enforce size limits on untrusted string fields.
bool IsFieldLengthValid(const std::string& value, size_t max_len) {
  return value.size() <= max_len;
}

// Reject overly large request bodies to limit abuse.
bool CheckBodySize(const httplib::Request& req, httplib::Response& res) {
  if (req.body.size() > kMaxBodyBytes) {
    res.status = 413;
    res.set_content("{\"error\":\"payload_too_large\"}", "application/json");
    return false;
  }
  return true;
}

// Apply CORS policy; return false when the Origin is not permitted.
bool ApplyCors(const httplib::Request& req, httplib::Response& res, const CorsConfig& cors) {
  const std::string origin = req.get_header_value("Origin");
  if (!origin.empty()) {
    if (cors.allow_all) {
      res.set_header("Access-Control-Allow-Origin", "*");
    } else if (cors.allowed.count(origin)) {
      res.set_header("Access-Control-Allow-Origin", origin);
      res.set_header("Vary", "Origin");
    } else {
      return false;
    }
  }
  res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.set_header("Access-Control-Max-Age", "86400");
  return true;
}

// Serve a static OpenAPI spec for docs and clients.
std::string BuildOpenApiSpec() {
  static const std::string spec = R"JSON({
  "openapi": "3.0.3",
  "info": {
    "title": "Secure Message API",
    "version": "1.0.0",
    "description": "Backend API for the Secure Message System."
  },
  "servers": [
    { "url": "http://localhost:8080" }
  ],
  "components": {
    "securitySchemes": {
      "bearerAuth": {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT"
      }
    }
  },
  "paths": {
    "/health": {
      "get": {
        "summary": "Health check",
        "responses": {
          "200": {
            "description": "OK",
            "content": { "application/json": { "example": { "status": "ok" } } }
          }
        }
      }
    },
    "/api/register": {
      "post": {
        "summary": "Register user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["username", "password", "public_key", "encrypted_private_key"],
                "properties": {
                  "username": { "type": "string" },
                  "password": { "type": "string" },
                  "public_key": { "type": "string" },
                  "encrypted_private_key": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Registered" },
          "400": { "description": "Invalid request" },
          "409": { "description": "User exists" }
        }
      }
    },
    "/api/login": {
      "post": {
        "summary": "Login user",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["username", "password"],
                "properties": {
                  "username": { "type": "string" },
                  "password": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "description": "Token issued" },
          "401": { "description": "Invalid credentials" }
        }
      }
    },
    "/api/logout": {
      "post": {
        "summary": "Logout user",
        "security": [ { "bearerAuth": [] } ],
        "responses": {
          "200": { "description": "Logged out" },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/me": {
      "get": {
        "summary": "Current user info",
        "security": [ { "bearerAuth": [] } ],
        "responses": {
          "200": { "description": "User details" },
          "401": { "description": "Unauthorized" }
        }
      }
    },
    "/api/users/{username}/public-key": {
      "get": {
        "summary": "Get public key by username",
        "security": [ { "bearerAuth": [] } ],
        "parameters": [
          {
            "name": "username",
            "in": "path",
            "required": true,
            "schema": { "type": "string" }
          }
        ],
        "responses": {
          "200": { "description": "Public key" },
          "404": { "description": "User not found" }
        }
      }
    },
    "/api/messages": {
      "post": {
        "summary": "Send message",
        "security": [ { "bearerAuth": [] } ],
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "required": ["recipient", "encrypted_key", "ciphertext", "iv"],
                "properties": {
                  "recipient": { "type": "string" },
                  "encrypted_key": { "type": "string" },
                  "ciphertext": { "type": "string" },
                  "iv": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Stored" },
          "401": { "description": "Unauthorized" }
        }
      },
      "get": {
        "summary": "List messages",
        "security": [ { "bearerAuth": [] } ],
        "parameters": [
          { "name": "with", "in": "query", "schema": { "type": "string" } },
          { "name": "limit", "in": "query", "schema": { "type": "integer" } },
          { "name": "order", "in": "query", "schema": { "type": "string", "enum": ["asc", "desc"] } },
          { "name": "before_id", "in": "query", "schema": { "type": "integer" } }
        ],
        "responses": {
          "200": { "description": "Messages list" },
          "401": { "description": "Unauthorized" }
        }
      }
    }
  }
})JSON";
  return spec;
}

// Create required tables if they do not exist yet.
void EnsureSchema(pqxx::connection& conn) {
  pqxx::work txn(conn);
  txn.exec(R"(
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      public_key TEXT NOT NULL,
      encrypted_private_key TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  )");

  txn.exec(R"(
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      recipient_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      encrypted_key TEXT NOT NULL,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  )");

  txn.commit();
}

// Fetch a user record by username (or nullopt if not found).
std::optional<DbUser> GetUserByUsername(pqxx::connection& conn, const std::string& username) {
  pqxx::work txn(conn);
  pqxx::result r = txn.exec_params(
      "SELECT id, username, password_hash, public_key, encrypted_private_key FROM users WHERE username = $1",
      username);
  txn.commit();
  if (r.empty()) {
    return std::nullopt;
  }
  DbUser user;
  user.id = r[0][0].as<int>();
  user.username = r[0][1].as<std::string>();
  user.password_hash = r[0][2].as<std::string>();
  user.public_key = r[0][3].as<std::string>();
  user.encrypted_private_key = r[0][4].as<std::string>();
  return user;
}

// Configure the server, routes, and start listening.
int main() {
  if (sodium_init() < 0) {
    std::fprintf(stderr, "Failed to initialize libsodium.\n");
    return 1;
  }

  try {
    pqxx::connection conn(GetDbUrl());
    EnsureSchema(conn);
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "Database init failed: %s\n", ex.what());
    return 1;
  }

  httplib::Server server;

  std::mutex token_mu;
  std::unordered_map<std::string, TokenInfo> tokens;
  std::chrono::system_clock::time_point last_token_cleanup = std::chrono::system_clock::now();

  RateLimiter login_ip_limiter;
  RateLimiter login_user_limiter;
  RateLimiter register_ip_limiter;
  RateLimiter register_user_limiter;

  CorsConfig cors;
  std::string cors_origin = GetEnvOrDefault("CORS_ORIGIN", "*");
  if (cors_origin != "*") {
    cors.allow_all = false;
    cors.allowed = SplitCsvToSet(cors_origin);
  }

  bool hsts_enabled = IsTruthy(GetEnvOrDefault("HSTS_ENABLED", ""));
  httplib::Headers default_headers = {
      {"Cache-Control", "no-store"},
      {"X-Content-Type-Options", "nosniff"},
  };
  if (hsts_enabled) {
    default_headers.emplace("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  server.set_default_headers(default_headers);

  server.Options(R"(/api/.*)", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    res.status = 204;
  });

  server.Get("/openapi.json", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    res.set_content(BuildOpenApiSpec(), "application/json");
  });

  server.Get("/api/docs", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    const std::string html = R"HTML(
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8"/>
    <title>Secure Message API Docs</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; line-height: 1.5; }
      code { background: #f3f3f3; padding: 2px 6px; border-radius: 4px; }
      h1 { margin-bottom: 0.5rem; }
      .muted { color: #666; }
      ul { margin-top: 0.5rem; }
    </style>
  </head>
  <body>
    <h1>Secure Message API</h1>
    <div class="muted">OpenAPI spec: <a href="/openapi.json">/openapi.json</a></div>
    <h2>Endpoints</h2>
    <ul>
      <li><code>GET /health</code></li>
      <li><code>POST /api/register</code></li>
      <li><code>POST /api/login</code></li>
      <li><code>POST /api/logout</code></li>
      <li><code>GET /api/me</code></li>
      <li><code>GET /api/users/{username}/public-key</code></li>
      <li><code>POST /api/messages</code></li>
      <li><code>GET /api/messages</code> (with, limit, order, before_id)</li>
    </ul>
    <p>Protected endpoints require <code>Authorization: Bearer &lt;token&gt;</code>.</p>
  </body>
</html>
)HTML";
    res.set_content(html, "text/html");
  });

  server.Get("/health", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    json out = { {"status", "ok"} };
    res.set_content(out.dump(), "application/json");
  });

  server.Post("/api/register", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    if (!CheckBodySize(req, res)) {
      return;
    }

    auto now = std::chrono::system_clock::now();
    if (!register_ip_limiter.Allow(req.remote_addr, 10, std::chrono::seconds(60), now)) {
      res.status = 429;
      res.set_content("{\"error\":\"rate_limited\"}", "application/json");
      return;
    }

    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_json\"}", "application/json");
      return;
    }

    const std::string username = body.value("username", "");
    const std::string password = body.value("password", "");
    const std::string public_key = body.value("public_key", "");
    const std::string encrypted_private_key = body.value("encrypted_private_key", "");

    if (username.empty() || password.empty() || public_key.empty() || encrypted_private_key.empty()) {
      res.status = 400;
      res.set_content("{\"error\":\"missing_fields\"}", "application/json");
      return;
    }
    if (!IsValidUsername(username)) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_username\"}", "application/json");
      return;
    }
    if (!IsValidPassword(password)) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_password\",\"message\":\"password must be 8-128 characters\"}", "application/json");
      return;
    }
    if (!IsFieldLengthValid(public_key, kMaxPublicKeyLen) ||
        !IsFieldLengthValid(encrypted_private_key, kMaxEncryptedPrivateKeyLen)) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_fields\"}", "application/json");
      return;
    }

    if (!register_user_limiter.Allow(username, 5, std::chrono::seconds(60), now)) {
      res.status = 429;
      res.set_content("{\"error\":\"rate_limited\"}", "application/json");
      return;
    }

    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(
            hash,
            password.c_str(),
            password.size(),
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
      res.status = 500;
      res.set_content("{\"error\":\"hash_failed\"}", "application/json");
      return;
    }

    try {
      pqxx::connection conn(GetDbUrl());
      auto existing = GetUserByUsername(conn, username);
      if (existing.has_value()) {
        res.status = 400;
        res.set_content("{\"error\":\"registration_failed\"}", "application/json");
        return;
      }

      pqxx::work txn(conn);
      txn.exec_params(
          "INSERT INTO users (username, password_hash, public_key, encrypted_private_key) VALUES ($1, $2, $3, $4)",
          username,
          std::string(hash),
          public_key,
          encrypted_private_key);
      txn.commit();

      res.status = 201;
      res.set_content("{\"status\":\"registered\"}", "application/json");
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "Register DB error: %s\n", ex.what());
      res.status = 500;
      res.set_content("{\"error\":\"db_error\"}", "application/json");
    }
  });

  server.Post("/api/login", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    if (!CheckBodySize(req, res)) {
      return;
    }

    auto now = std::chrono::system_clock::now();
    if (!login_ip_limiter.Allow(req.remote_addr, 20, std::chrono::seconds(60), now)) {
      res.status = 429;
      res.set_content("{\"error\":\"rate_limited\"}", "application/json");
      return;
    }

    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_json\"}", "application/json");
      return;
    }

    const std::string username = body.value("username", "");
    const std::string password = body.value("password", "");

    if (username.empty() || password.empty()) {
      res.status = 400;
      res.set_content("{\"error\":\"missing_fields\"}", "application/json");
      return;
    }
    if (!login_user_limiter.Allow(username, 10, std::chrono::seconds(60), now)) {
      res.status = 429;
      res.set_content("{\"error\":\"rate_limited\"}", "application/json");
      return;
    }

    try {
      pqxx::connection conn(GetDbUrl());
      auto user = GetUserByUsername(conn, username);
      if (!user.has_value()) {
        res.status = 401;
        res.set_content("{\"error\":\"invalid_credentials\"}", "application/json");
        return;
      }

      if (crypto_pwhash_str_verify(user->password_hash.c_str(), password.c_str(), password.size()) != 0) {
        res.status = 401;
        res.set_content("{\"error\":\"invalid_credentials\"}", "application/json");
        return;
      }

      std::string token = GenerateToken();
      auto expires_at = std::chrono::system_clock::now() + std::chrono::hours(1);
      {
        std::lock_guard<std::mutex> lock(token_mu);
        tokens[token] = TokenInfo{username, expires_at};
      }

      json out = { {"token", token}, {"expires_in", 3600} };
      res.set_content(out.dump(), "application/json");
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "Login DB error: %s\n", ex.what());
      res.status = 500;
      res.set_content("{\"error\":\"db_error\"}", "application/json");
    }
  });

  server.Post("/api/logout", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    auto token_opt = ExtractBearerToken(req);
    if (!token_opt.has_value()) {
      res.status = 401;
      res.set_content("{\"error\":\"unauthorized\"}", "application/json");
      return;
    }

    auto now = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(token_mu);
    if (now - last_token_cleanup > std::chrono::minutes(5)) {
      for (auto it = tokens.begin(); it != tokens.end();) {
        if (it->second.expires_at < now) {
          it = tokens.erase(it);
        } else {
          ++it;
        }
      }
      last_token_cleanup = now;
    }
    auto it = tokens.find(*token_opt);
    if (it == tokens.end() || it->second.expires_at < now) {
      if (it != tokens.end()) {
        tokens.erase(it);
      }
      res.status = 401;
      res.set_content("{\"error\":\"unauthorized\"}", "application/json");
      return;
    }
    tokens.erase(it);
    res.set_content("{\"status\":\"logged_out\"}", "application/json");
  });

  server.Get("/api/me", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    auto auth_user = ValidateToken(req, tokens, token_mu, last_token_cleanup);
    if (!auth_user.has_value()) {
      res.status = 401;
      res.set_content("{\"error\":\"unauthorized\"}", "application/json");
      return;
    }

    try {
      pqxx::connection conn(GetDbUrl());
      auto user = GetUserByUsername(conn, *auth_user);
      if (!user.has_value()) {
        res.status = 404;
        res.set_content("{\"error\":\"user_not_found\"}", "application/json");
        return;
      }

      json out = {
          {"username", user->username},
          {"public_key", user->public_key},
          {"encrypted_private_key", user->encrypted_private_key}
      };
      res.set_content(out.dump(), "application/json");
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "Me DB error: %s\n", ex.what());
      res.status = 500;
      res.set_content("{\"error\":\"db_error\"}", "application/json");
    }
  });

  server.Get(R"(/api/users/(.*)/public-key)", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    auto auth_user = ValidateToken(req, tokens, token_mu, last_token_cleanup);
    if (!auth_user.has_value()) {
      res.status = 401;
      res.set_content("{\"error\":\"unauthorized\"}", "application/json");
      return;
    }

    std::string username = req.matches[1];
    if (!IsValidUsername(username)) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_username\"}", "application/json");
      return;
    }
    try {
      pqxx::connection conn(GetDbUrl());
      auto user = GetUserByUsername(conn, username);
      if (!user.has_value()) {
        res.status = 404;
        res.set_content("{\"error\":\"user_not_found\"}", "application/json");
        return;
      }

      json out = { {"username", username}, {"public_key", user->public_key} };
      res.set_content(out.dump(), "application/json");
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "Public key DB error: %s\n", ex.what());
      res.status = 500;
      res.set_content("{\"error\":\"db_error\"}", "application/json");
    }
  });

  server.Post("/api/messages", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    if (!CheckBodySize(req, res)) {
      return;
    }
    auto auth_user = ValidateToken(req, tokens, token_mu, last_token_cleanup);
    if (!auth_user.has_value()) {
      res.status = 401;
      res.set_content("{\"error\":\"unauthorized\"}", "application/json");
      return;
    }

    json body;
    try {
      body = json::parse(req.body);
    } catch (...) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_json\"}", "application/json");
      return;
    }

    const std::string recipient = body.value("recipient", "");
    const std::string encrypted_key = body.value("encrypted_key", "");
    const std::string ciphertext = body.value("ciphertext", "");
    const std::string iv = body.value("iv", "");

    if (recipient.empty() || encrypted_key.empty() || ciphertext.empty() || iv.empty()) {
      res.status = 400;
      res.set_content("{\"error\":\"missing_fields\"}", "application/json");
      return;
    }
    if (!IsValidUsername(recipient)) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_username\"}", "application/json");
      return;
    }
    if (!IsFieldLengthValid(encrypted_key, kMaxEncryptedKeyLen) ||
        !IsFieldLengthValid(ciphertext, kMaxCiphertextLen) ||
        !IsFieldLengthValid(iv, kMaxIvLen)) {
      res.status = 400;
      res.set_content("{\"error\":\"invalid_fields\"}", "application/json");
      return;
    }

    try {
      pqxx::connection conn(GetDbUrl());
      auto sender = GetUserByUsername(conn, *auth_user);
      auto recipient_user = GetUserByUsername(conn, recipient);
      if (!sender.has_value() || !recipient_user.has_value()) {
        res.status = 404;
        res.set_content("{\"error\":\"recipient_not_found\"}", "application/json");
        return;
      }

      pqxx::work txn(conn);
      pqxx::result r = txn.exec_params(
          "INSERT INTO messages (sender_id, recipient_id, encrypted_key, ciphertext, iv) VALUES ($1, $2, $3, $4, $5) RETURNING id",
          sender->id,
          recipient_user->id,
          encrypted_key,
          ciphertext,
          iv);
      txn.commit();

      json out = { {"status", "stored"}, {"id", r[0][0].as<int>()} };
      res.status = 201;
      res.set_content(out.dump(), "application/json");
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "Message insert DB error: %s\n", ex.what());
      res.status = 500;
      res.set_content("{\"error\":\"db_error\"}", "application/json");
    }
  });

  server.Get("/api/messages", [&](const httplib::Request& req, httplib::Response& res) {
    if (!ApplyCors(req, res, cors)) {
      res.status = 403;
      res.set_content("{\"error\":\"cors_denied\"}", "application/json");
      return;
    }
    auto auth_user = ValidateToken(req, tokens, token_mu, last_token_cleanup);
    if (!auth_user.has_value()) {
      res.status = 401;
      res.set_content("{\"error\":\"unauthorized\"}", "application/json");
      return;
    }

    std::string with_user = req.get_param_value("with");
    std::string order = req.get_param_value("order");
    std::string before_id_param = req.get_param_value("before_id");
    std::string limit_param = req.get_param_value("limit");
    std::string order_sql = "ASC";
    if (order == "desc") {
      order_sql = "DESC";
    }
    // Pagination: server-enforced max limit with optional client override.
    int limit = 200;
    if (!limit_param.empty()) {
      try {
        int parsed = std::stoi(limit_param);
        if (parsed > 0) {
          limit = std::min(parsed, 200);
        }
      } catch (...) {
        // Ignore invalid limit.
      }
    }
    // "before_id" provides keyset pagination by message id.
    std::optional<int> before_id;
    if (!before_id_param.empty()) {
      try {
        int parsed = std::stoi(before_id_param);
        if (parsed > 0) {
          before_id = parsed;
        }
      } catch (...) {
        // Ignore invalid before_id.
      }
    }

    try {
      pqxx::connection conn(GetDbUrl());
      auto me = GetUserByUsername(conn, *auth_user);
      if (!me.has_value()) {
        res.status = 401;
        res.set_content("{\"error\":\"unauthorized\"}", "application/json");
        return;
      }

      std::optional<int> with_id;
      if (!with_user.empty()) {
        auto other = GetUserByUsername(conn, with_user);
        if (!other.has_value()) {
          res.status = 404;
          res.set_content("{\"error\":\"user_not_found\"}", "application/json");
          return;
        }
        with_id = other->id;
      }

      pqxx::work txn(conn);
      pqxx::result r;
      if (with_id.has_value()) {
        if (before_id.has_value()) {
          r = txn.exec_params(
              "SELECT m.id, su.username, ru.username, m.encrypted_key, m.ciphertext, m.iv, m.created_at "
              "FROM messages m "
              "JOIN users su ON m.sender_id = su.id "
              "JOIN users ru ON m.recipient_id = ru.id "
              "WHERE ((m.sender_id = $1 AND m.recipient_id = $2) OR (m.sender_id = $2 AND m.recipient_id = $1)) "
              "AND m.id < $3 "
              "ORDER BY m.id " + order_sql + " "
              "LIMIT $4",
              me->id,
              *with_id,
              *before_id,
              limit);
        } else {
          r = txn.exec_params(
              "SELECT m.id, su.username, ru.username, m.encrypted_key, m.ciphertext, m.iv, m.created_at "
              "FROM messages m "
              "JOIN users su ON m.sender_id = su.id "
              "JOIN users ru ON m.recipient_id = ru.id "
              "WHERE (m.sender_id = $1 AND m.recipient_id = $2) OR (m.sender_id = $2 AND m.recipient_id = $1) "
              "ORDER BY m.id " + order_sql + " "
              "LIMIT $3",
              me->id,
              *with_id,
              limit);
        }
      } else {
        if (before_id.has_value()) {
          r = txn.exec_params(
              "SELECT m.id, su.username, ru.username, m.encrypted_key, m.ciphertext, m.iv, m.created_at "
              "FROM messages m "
              "JOIN users su ON m.sender_id = su.id "
              "JOIN users ru ON m.recipient_id = ru.id "
              "WHERE (m.sender_id = $1 OR m.recipient_id = $1) "
              "AND m.id < $2 "
              "ORDER BY m.id " + order_sql + " "
              "LIMIT $3",
              me->id,
              *before_id,
              limit);
        } else {
          r = txn.exec_params(
              "SELECT m.id, su.username, ru.username, m.encrypted_key, m.ciphertext, m.iv, m.created_at "
              "FROM messages m "
              "JOIN users su ON m.sender_id = su.id "
              "JOIN users ru ON m.recipient_id = ru.id "
              "WHERE m.sender_id = $1 OR m.recipient_id = $1 "
              "ORDER BY m.id " + order_sql + " "
              "LIMIT $2",
              me->id,
              limit);
        }
      }
      txn.commit();

      json out = json::array();
      for (const auto& row : r) {
        out.push_back({
            {"id", row[0].as<int>()},
            {"sender", row[1].as<std::string>()},
            {"recipient", row[2].as<std::string>()},
            {"encrypted_key", row[3].as<std::string>()},
            {"ciphertext", row[4].as<std::string>()},
            {"iv", row[5].as<std::string>()},
            {"created_at", row[6].as<std::string>()}
        });
      }
      res.set_content(out.dump(), "application/json");
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "Message list DB error: %s\n", ex.what());
      res.status = 500;
      res.set_content("{\"error\":\"db_error\"}", "application/json");
    }
  });

  const char* host = "0.0.0.0";
  int port = 8080;
  if (const char* env_port = std::getenv("PORT")) {
    try {
      int parsed = std::stoi(env_port);
      if (parsed > 0 && parsed < 65536) {
        port = parsed;
      }
    } catch (...) {
      // Ignore invalid PORT values.
    }
  }

  std::printf("Secure Message Backend listening on %s:%d\n", host, port);
  server.listen(host, port);
  return 0;
}
