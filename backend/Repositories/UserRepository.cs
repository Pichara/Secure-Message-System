using Npgsql;
using SecureMessageBackend.Models;
using SecureMessageBackend.Services;

namespace SecureMessageBackend.Repositories;

public class UserRepository
{
    private readonly DatabaseService _databaseService;

    public UserRepository(DatabaseService databaseService)
    {
        _databaseService = databaseService;
    }

    /// <summary>
    /// Gets a user by username
    /// </summary>
    public async Task<DbUser?> GetByUsernameAsync(string username)
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            SELECT id, username, password_hash, public_key, encrypted_private_key, role
            FROM users WHERE username = $1
        ", conn);
        cmd.Parameters.AddWithValue(username);

        await using var reader = await cmd.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return new DbUser
            {
                Id = reader.GetInt32(0),
                Username = reader.GetString(1),
                PasswordHash = reader.GetString(2),
                PublicKey = reader.GetString(3),
                EncryptedPrivateKey = reader.GetString(4),
                Role = reader.IsDBNull(5) ? Constants.UserRole : reader.GetString(5)
            };
        }

        return null;
    }

    /// <summary>
    /// Creates a new user
    /// </summary>
    public async Task CreateAsync(string username, string passwordHash, string publicKey, string encryptedPrivateKey, string role = Constants.UserRole)
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO users (username, password_hash, public_key, encrypted_private_key, role)
            VALUES ($1, $2, $3, $4, $5)
        ", conn);
        cmd.Parameters.AddWithValue(username);
        cmd.Parameters.AddWithValue(passwordHash);
        cmd.Parameters.AddWithValue(publicKey);
        cmd.Parameters.AddWithValue(encryptedPrivateKey);
        cmd.Parameters.AddWithValue(role);

        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Gets all usernames (admin only)
    /// </summary>
    public async Task<List<string>> GetAllUsernamesAsync()
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            SELECT username FROM users ORDER BY username ASC
        ", conn);

        var result = new List<string>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            result.Add(reader.GetString(0));
        }

        return result;
    }

    /// <summary>
    /// Checks if a user exists by username
    /// </summary>
    public async Task<bool> ExistsAsync(string username)
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            SELECT COUNT(*) FROM users WHERE username = $1
        ", conn);
        cmd.Parameters.AddWithValue(username);

        var count = (long?)await cmd.ExecuteScalarAsync() ?? 0;
        return count > 0;
    }
}
