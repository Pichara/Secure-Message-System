using Npgsql;
using SecureMessageBackend.Models;
using SecureMessageBackend.Services;

namespace SecureMessageBackend.Repositories;

public class MessageRepository
{
    private readonly DatabaseService _databaseService;

    public MessageRepository(DatabaseService databaseService)
    {
        _databaseService = databaseService;
    }

    /// <summary>
    /// Creates a new message
    /// </summary>
    public async Task<int> CreateAsync(int senderId, int recipientId, string encryptedKey, string ciphertext, string iv)
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO messages (sender_id, recipient_id, encrypted_key, ciphertext, iv)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        ", conn);
        cmd.Parameters.AddWithValue(senderId);
        cmd.Parameters.AddWithValue(recipientId);
        cmd.Parameters.AddWithValue(encryptedKey);
        cmd.Parameters.AddWithValue(ciphertext);
        cmd.Parameters.AddWithValue(iv);

        var result = await cmd.ExecuteScalarAsync();
        return Convert.ToInt32(result);
    }

    /// <summary>
    /// Gets messages for a user
    /// </summary>
    public async Task<List<DbMessage>> GetForUserAsync(
        int userId,
        string? withUsername = null,
        int? beforeId = null,
        int limit = 200,
        string order = "asc")
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        string orderSql = order.ToLower() == "desc" ? "DESC" : "ASC";
        string? withClause = null;
        string? beforeClause = null;

        List<NpgsqlParameter> parameters = new();

        if (!string.IsNullOrEmpty(withUsername))
        {
            // Get the user ID for the "with" username
            await using var userCmd = new NpgsqlCommand(
                "SELECT id FROM users WHERE username = $1",
                conn);
            userCmd.Parameters.AddWithValue(withUsername);
            var withUserIdObj = await userCmd.ExecuteScalarAsync();

            if (withUserIdObj == null)
            {
                return new List<DbMessage>();
            }

            int withUserId = Convert.ToInt32(withUserIdObj);
            withClause = $"(m.sender_id = ${parameters.Count + 1} AND m.recipient_id = ${parameters.Count + 2}) OR (m.sender_id = ${parameters.Count + 2} AND m.recipient_id = ${parameters.Count + 1})";
            parameters.Add(new NpgsqlParameter { Value = userId });
            parameters.Add(new NpgsqlParameter { Value = withUserId });
        }
        else
        {
            withClause = $"m.sender_id = ${parameters.Count + 1} OR m.recipient_id = ${parameters.Count + 1}";
            parameters.Add(new NpgsqlParameter { Value = userId });
        }

        if (beforeId.HasValue)
        {
            beforeClause = $"m.id < ${parameters.Count + 1}";
            parameters.Add(new NpgsqlParameter { Value = beforeId.Value });
        }

        string limitClause = $"LIMIT ${parameters.Count + 1}";
        parameters.Add(new NpgsqlParameter { Value = limit });

        string query = $@"
            SELECT m.id, su.username, ru.username, m.encrypted_key, m.ciphertext, m.iv, m.created_at
            FROM messages m
            JOIN users su ON m.sender_id = su.id
            JOIN users ru ON m.recipient_id = ru.id
            WHERE {withClause}";

        if (beforeClause != null)
        {
            query += $" AND {beforeClause}";
        }

        query += $" ORDER BY m.id {orderSql} {limitClause}";

        await using var cmd = new NpgsqlCommand(query, conn);
        cmd.Parameters.AddRange(parameters.ToArray());

        var result = new List<DbMessage>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            result.Add(new DbMessage
            {
                Id = reader.GetInt32(0),
                Sender = reader.GetString(1),
                Recipient = reader.GetString(2),
                EncryptedKey = reader.GetString(3),
                Ciphertext = reader.GetString(4),
                Iv = reader.GetString(5),
                CreatedAt = reader.GetDateTime(6)
            });
        }

        return result;
    }
}
