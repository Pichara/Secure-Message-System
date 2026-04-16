using SecureMessageBackend.Models;
using System.Security.Cryptography;

namespace SecureMessageBackend.Services;

public class TokenService
{
    private readonly object _lock = new();
    private readonly Dictionary<string, TokenInfo> _tokens = new();
    private DateTime _lastCleanup = DateTime.UtcNow;

    private class TokenInfo
    {
        public string Username { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
    }

    /// <summary>
    /// Generates a new random token
    /// </summary>
    public string GenerateToken()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Creates and stores a token for a user
    /// </summary>
    public string CreateToken(string username)
    {
        string token = GenerateToken();
        var expiresAt = DateTime.UtcNow.Add(Constants.TokenTtl);

        lock (_lock)
        {
            _tokens[token] = new TokenInfo
            {
                Username = username,
                ExpiresAt = expiresAt
            };
        }

        return token;
    }

    /// <summary>
    /// Validates a token and returns the associated username if valid
    /// </summary>
    public string? ValidateToken(string token)
    {
        CleanupExpiredTokens();

        lock (_lock)
        {
            if (_tokens.TryGetValue(token, out var info))
            {
                if (info.ExpiresAt > DateTime.UtcNow)
                {
                    return info.Username;
                }
                else
                {
                    _tokens.Remove(token);
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Invalidates a token (logout)
    /// </summary>
    public bool InvalidateToken(string token)
    {
        CleanupExpiredTokens();

        lock (_lock)
        {
            if (_tokens.TryGetValue(token, out var info))
            {
                if (info.ExpiresAt > DateTime.UtcNow)
                {
                    _tokens.Remove(token);
                    return true;
                }
                else
                {
                    _tokens.Remove(token);
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Invalidates all active tokens for a given username
    /// </summary>
    public void InvalidateTokensForUser(string username)
    {
        CleanupExpiredTokens();

        lock (_lock)
        {
            var matchingTokens = _tokens
                .Where(kvp => string.Equals(kvp.Value.Username, username, StringComparison.Ordinal))
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var token in matchingTokens)
            {
                _tokens.Remove(token);
            }
        }
    }

    /// <summary>
    /// Periodically removes expired tokens
    /// </summary>
    private void CleanupExpiredTokens()
    {
        var now = DateTime.UtcNow;
        if (now - _lastCleanup < Constants.TokenCleanupInterval)
        {
            return;
        }

        lock (_lock)
        {
            var expired = _tokens
                .Where(kvp => kvp.Value.ExpiresAt <= now)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in expired)
            {
                _tokens.Remove(key);
            }

            _lastCleanup = now;
        }
    }
}
