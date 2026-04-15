using Npgsql;
using SecureMessageBackend.Models;

namespace SecureMessageBackend.Services;

public class DatabaseService
{
    private readonly string _connectionString;
    private readonly PasswordService _passwordService;

    public DatabaseService(IConfiguration configuration, PasswordService passwordService)
    {
        string? dbUrl = configuration.GetConnectionString("DefaultConnection")
            ?? Environment.GetEnvironmentVariable("DATABASE_URL");

        if (string.IsNullOrEmpty(dbUrl))
        {
            dbUrl = "postgresql://postgres:postgres@localhost:5432/secure_message";
        }

        _connectionString = ConvertDatabaseUrlToNpgsqlConnectionString(dbUrl);
        _passwordService = passwordService;
    }

    private string ConvertDatabaseUrlToNpgsqlConnectionString(string databaseUrl)
    {
        // Parse DATABASE_URL format: postgresql://user:pass@host:port/db
        var uri = new Uri(databaseUrl);
        var userInfo = uri.UserInfo.Split(':');
        var username = Uri.UnescapeDataString(userInfo[0]);
        var password = userInfo.Length > 1 ? Uri.UnescapeDataString(string.Join(":", userInfo.Skip(1))) : "";
        var host = uri.Host;
        var port = uri.Port > 0 ? uri.Port : 5432;
        var database = uri.AbsolutePath.TrimStart('/');

        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = port,
            Username = username,
            Password = password,
            Database = database
        };

        return builder.ToString();
    }

    /// <summary>
    /// Gets a new database connection
    /// </summary>
    public NpgsqlConnection GetConnection()
    {
        return new NpgsqlConnection(_connectionString);
    }

    /// <summary>
    /// Initializes the database schema and ensures the ADMIN user exists
    /// </summary>
    public async Task InitializeAsync()
    {
        using var conn = GetConnection();
        await conn.OpenAsync();

        await EnsureSchemaAsync(conn);
        await EnsureBootstrapAdminAccountAsync(conn);
    }

    private async Task EnsureSchemaAsync(NpgsqlConnection conn)
    {
        using var txn = await conn.BeginTransactionAsync();

        // Create users table
        await using (var cmd = new NpgsqlCommand(@"
            CREATE TABLE IF NOT EXISTS users (
              id SERIAL PRIMARY KEY,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              public_key TEXT NOT NULL,
              encrypted_private_key TEXT NOT NULL,
              role TEXT NOT NULL DEFAULT 'user',
              created_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
        ", conn, txn))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        // Add role column if it doesn't exist (for backward compatibility)
        await using (var cmd = new NpgsqlCommand(@"
            ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
        ", conn, txn))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        // Update NULL roles to 'user'
        await using (var cmd = new NpgsqlCommand(@"
            UPDATE users SET role = 'user' WHERE role IS NULL OR role = '';
        ", conn, txn))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        // Create messages table
        await using (var cmd = new NpgsqlCommand(@"
            CREATE TABLE IF NOT EXISTS messages (
              id SERIAL PRIMARY KEY,
              sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              recipient_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              encrypted_key TEXT NOT NULL,
              ciphertext TEXT NOT NULL,
              iv TEXT NOT NULL,
              created_at TIMESTAMP NOT NULL DEFAULT NOW()
            );
        ", conn, txn))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        // Create contacts table
        await using (var cmd = new NpgsqlCommand(@"
            CREATE TABLE IF NOT EXISTS contacts (
              id SERIAL PRIMARY KEY,
              owner_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              alias TEXT NOT NULL,
              contact_user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
              created_at TIMESTAMP NOT NULL DEFAULT NOW(),
              UNIQUE(owner_user_id, alias)
            );
        ", conn, txn))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        await txn.CommitAsync();
    }

    private async Task EnsureBootstrapAdminAccountAsync(NpgsqlConnection conn)
    {
        string passwordHash = _passwordService.HashPassword(Constants.BootstrapAdminPassword);

        using var txn = await conn.BeginTransactionAsync();

        // Check if ADMIN user exists
        await using (var checkCmd = new NpgsqlCommand(
            "SELECT id FROM users WHERE username = $1",
            conn,
            txn))
        {
            checkCmd.Parameters.AddWithValue(Constants.AdminUsername);
            var result = await checkCmd.ExecuteScalarAsync();

            if (result == null)
            {
                // Create ADMIN user
                await using (var insertCmd = new NpgsqlCommand(@"
                    INSERT INTO users (username, password_hash, public_key, encrypted_private_key, role)
                    VALUES ($1, $2, $3, $4, $5)
                ", conn, txn))
                {
                    insertCmd.Parameters.AddWithValue(Constants.AdminUsername);
                    insertCmd.Parameters.AddWithValue(passwordHash);
                    insertCmd.Parameters.AddWithValue(Constants.BootstrapAdminPublicKey);
                    insertCmd.Parameters.AddWithValue(Constants.BootstrapAdminEncryptedPrivateKey);
                    insertCmd.Parameters.AddWithValue(Constants.AdminRole);
                    await insertCmd.ExecuteNonQueryAsync();
                }
            }
            else
            {
                // Update ADMIN user password and role
                await using (var updateCmd = new NpgsqlCommand(@"
                    UPDATE users SET password_hash = $2, role = $3 WHERE username = $1
                ", conn, txn))
                {
                    updateCmd.Parameters.AddWithValue(Constants.AdminUsername);
                    updateCmd.Parameters.AddWithValue(passwordHash);
                    updateCmd.Parameters.AddWithValue(Constants.AdminRole);
                    await updateCmd.ExecuteNonQueryAsync();
                }
            }
        }

        await txn.CommitAsync();
    }
}
