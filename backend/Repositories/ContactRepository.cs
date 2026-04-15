using Npgsql;
using SecureMessageBackend.Models;
using SecureMessageBackend.Services;

namespace SecureMessageBackend.Repositories;

public class ContactRepository
{
    private readonly DatabaseService _databaseService;

    public ContactRepository(DatabaseService databaseService)
    {
        _databaseService = databaseService;
    }

    /// <summary>
    /// Gets all contacts for a user
    /// </summary>
    public async Task<List<DbContact>> GetForUserAsync(int ownerUserId)
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            SELECT c.alias, u.username
            FROM contacts c
            JOIN users u ON c.contact_user_id = u.id
            WHERE c.owner_user_id = $1
            ORDER BY c.alias ASC, u.username ASC
        ", conn);
        cmd.Parameters.AddWithValue(ownerUserId);

        var result = new List<DbContact>();
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            result.Add(new DbContact
            {
                Alias = reader.GetString(0),
                Username = reader.GetString(1)
            });
        }

        return result;
    }

    /// <summary>
    /// Saves or updates a contact
    /// </summary>
    public async Task SaveAsync(int ownerUserId, string alias, int contactUserId)
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO contacts (owner_user_id, alias, contact_user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (owner_user_id, alias)
            DO UPDATE SET contact_user_id = EXCLUDED.contact_user_id
        ", conn);
        cmd.Parameters.AddWithValue(ownerUserId);
        cmd.Parameters.AddWithValue(alias);
        cmd.Parameters.AddWithValue(contactUserId);

        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Deletes a contact by alias for a user
    /// </summary>
    public async Task<bool> DeleteAsync(int ownerUserId, string alias)
    {
        using var conn = _databaseService.GetConnection();
        await conn.OpenAsync();

        await using var cmd = new NpgsqlCommand(@"
            DELETE FROM contacts WHERE owner_user_id = $1 AND alias = $2 RETURNING id
        ", conn);
        cmd.Parameters.AddWithValue(ownerUserId);
        cmd.Parameters.AddWithValue(alias);

        var result = await cmd.ExecuteScalarAsync();
        return result != null;
    }
}
