using Konscious.Security.Cryptography;
using SecureMessageBackend.Models;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace SecureMessageBackend.Services;

public class PasswordService
{
    // These are the libsodium moderate limits used by crypto_pwhash_OPSLIMIT_MODERATE
    // and crypto_pwhash_MEMLIMIT_MODERATE
    private const int Argon2Iterations = 3;
    private const int Argon2Memory = 65536; // 64 MB
    private const int Argon2Parallelism = 2;
    private const int Argon2HashLength = 32;
    private const int Argon2SaltLength = 16;

    /// <summary>
    /// Hashes a password using Argon2id with libsodium-compatible parameters
    /// </summary>
    public string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(Argon2SaltLength);

        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = Argon2Parallelism,
            Iterations = Argon2Iterations,
            MemorySize = Argon2Memory,
        };

        byte[] hash = argon2.GetBytes(Argon2HashLength);

        // Format as PHC string: $argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
        // Use standard base64 encoding without padding for PHC compatibility
        string saltBase64 = Convert.ToBase64String(salt).TrimEnd('=');
        string hashBase64 = Convert.ToBase64String(hash).TrimEnd('=');

        return $"$argon2id$v=19$m={Argon2Memory},t={Argon2Iterations},p={Argon2Parallelism}${saltBase64}${hashBase64}";
    }

    /// <summary>
    /// Verifies a password against an Argon2id hash (libsodium compatible format)
    /// </summary>
    public bool VerifyPassword(string hash, string password)
    {
        try
        {
            // Parse PHC format: $argon2id$v=19$m=65536,t=3,p=2$<base64 salt>$<base64 hash>
            var parts = hash.Split('$');
            if (parts.Length < 6 || parts[1] != "argon2id")
            {
                return false;
            }

            // Extract parameters (optional, for parsing)
            var paramPart = parts[4].Split(',');
            int memory = Argon2Memory;
            int iterations = Argon2Iterations;
            int parallelism = Argon2Parallelism;

            foreach (var param in paramPart)
            {
                var kv = param.Split('=');
                if (kv.Length == 2)
                {
                    switch (kv[0])
                    {
                        case "m": memory = int.Parse(kv[1]); break;
                        case "t": iterations = int.Parse(kv[1]); break;
                        case "p": parallelism = int.Parse(kv[1]); break;
                    }
                }
            }

            string saltBase64 = parts[5];
            string hashBase64 = parts[6];

            // Decode base64 (PHC uses standard base64 without padding)
            byte[] salt = Base64UrlDecode(saltBase64);
            byte[] expectedHash = Base64UrlDecode(hashBase64);

            // Compute hash with the same parameters
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = parallelism,
                Iterations = iterations,
                MemorySize = memory,
            };

            byte[] computedHash = argon2.GetBytes(expectedHash.Length);

            // Constant-time comparison
            return CryptographicOperations.FixedTimeEquals(expectedHash, computedHash);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Decodes a base64url string (base64 without padding) to bytes
    /// </summary>
    private static byte[] Base64UrlDecode(string base64Url)
    {
        // Add padding if needed
        string base64 = base64Url;
        int padding = 4 - (base64.Length % 4);
        if (padding < 4)
        {
            base64 += new string('=', padding);
        }
        return Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Validates password according to policy
    /// </summary>
    public (bool IsValid, string? ErrorMessage) ValidatePassword(string password)
    {
        if (password.Length < Constants.MinPasswordLen || password.Length > Constants.MaxPasswordLen)
        {
            return (false, "password must be 8-128 characters and include at least one number and one special character");
        }

        bool hasDigit = false;
        bool hasSpecial = false;

        foreach (char ch in password)
        {
            if (char.IsDigit(ch))
            {
                hasDigit = true;
            }
            else if (!char.IsLetterOrDigit(ch) && !char.IsWhiteSpace(ch))
            {
                hasSpecial = true;
            }
        }

        if (!hasDigit || !hasSpecial)
        {
            return (false, "password must be 8-128 characters and include at least one number and one special character");
        }

        return (true, null);
    }

    /// <summary>
    /// Validates username according to policy
    /// </summary>
    public bool IsValidUsername(string username)
    {
        if (username.Length < Constants.MinUsernameLen || username.Length > Constants.MaxUsernameLen)
        {
            return false;
        }

        foreach (char ch in username)
        {
            if (char.IsLetterOrDigit(ch))
            {
                continue;
            }
            if (ch == '_' || ch == '-' || ch == '.')
            {
                continue;
            }
            return false;
        }

        return true;
    }

    /// <summary>
    /// Validates field length
    /// </summary>
    public bool IsFieldLengthValid(string value, int maxLength)
    {
        return value.Length <= maxLength;
    }
}
