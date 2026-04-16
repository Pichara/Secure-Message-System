using Npgsql;
using SecureMessageBackend.Models;

namespace SecureMessageBackend.Services;

public class DatabaseService
{
    private readonly string _connectionString;
    private readonly PasswordService _passwordService;
    private readonly string? _bootstrapAdminUsername;
    private readonly string? _bootstrapAdminPassword;
    private readonly string _bootstrapAdminPublicKey;
    private readonly string _bootstrapAdminEncryptedPrivateKey;

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
        _bootstrapAdminUsername = Environment.GetEnvironmentVariable("BOOTSTRAP_ADMIN_USERNAME");
        _bootstrapAdminPassword = Environment.GetEnvironmentVariable("BOOTSTRAP_ADMIN_PASSWORD");
        _bootstrapAdminPublicKey = Environment.GetEnvironmentVariable("BOOTSTRAP_ADMIN_PUBLIC_KEY")
            ?? Constants.BootstrapAdminPublicKey;
        _bootstrapAdminEncryptedPrivateKey = Environment.GetEnvironmentVariable("BOOTSTRAP_ADMIN_ENCRYPTED_PRIVATE_KEY")
            ?? Constants.BootstrapAdminEncryptedPrivateKey;
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
        if (string.IsNullOrWhiteSpace(_bootstrapAdminUsername) || string.IsNullOrWhiteSpace(_bootstrapAdminPassword))
        {
            Console.WriteLine("Bootstrap admin skipped: BOOTSTRAP_ADMIN_USERNAME/BOOTSTRAP_ADMIN_PASSWORD not set.");
            return;
        }

        string passwordHash = _passwordService.HashPassword(_bootstrapAdminPassword);

        using var txn = await conn.BeginTransactionAsync();

        // Check if configured bootstrap admin exists
        await using (var checkCmd = new NpgsqlCommand(
            "SELECT id FROM users WHERE username = $1",
            conn,
            txn))
        {
            checkCmd.Parameters.AddWithValue(_bootstrapAdminUsername);
            var result = await checkCmd.ExecuteScalarAsync();

            if (result == null)
            {
                // Create bootstrap admin user from environment configuration.
                await using (var insertCmd = new NpgsqlCommand(@"
                    INSERT INTO users (username, password_hash, public_key, encrypted_private_key, role)
                    VALUES ($1, $2, $3, $4, $5)
                ", conn, txn))
                {
                    insertCmd.Parameters.AddWithValue(_bootstrapAdminUsername);
                    insertCmd.Parameters.AddWithValue(passwordHash);
                    insertCmd.Parameters.AddWithValue(_bootstrapAdminPublicKey);
                    insertCmd.Parameters.AddWithValue(_bootstrapAdminEncryptedPrivateKey);
                    insertCmd.Parameters.AddWithValue(Constants.AdminRole);
                    await insertCmd.ExecuteNonQueryAsync();
                }
            }
            else
            {
                // Update bootstrap admin password and role on every startup.
                await using (var updateCmd = new NpgsqlCommand(@"
                    UPDATE users SET password_hash = $2, role = $3 WHERE username = $1
                ", conn, txn))
                {
                    updateCmd.Parameters.AddWithValue(_bootstrapAdminUsername);
                    updateCmd.Parameters.AddWithValue(passwordHash);
                    updateCmd.Parameters.AddWithValue(Constants.AdminRole);
                    await updateCmd.ExecuteNonQueryAsync();
                }
            }
        }

        await txn.CommitAsync();
    }
}
