using System.Text.Json.Serialization;

namespace SecureMessageBackend.Models;

public class ErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

public class LoginResponse
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = string.Empty;

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;
}

public class MeResponse
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = string.Empty;

    [JsonPropertyName("encrypted_private_key")]
    public string EncryptedPrivateKey { get; set; } = string.Empty;

    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;
}

public class ContactResponse
{
    [JsonPropertyName("alias")]
    public string Alias { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
}

public class UsersListResponse
{
    [JsonPropertyName("users")]
    public List<UserListItem> Users { get; set; } = new();
}

public class UserListItem
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;
}

public class PublicKeyResponse
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = string.Empty;
}

public class MessageStoredResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = "stored";

    [JsonPropertyName("id")]
    public int Id { get; set; }
}

public class StatusResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;
}

public class HealthResponse
{
    [JsonPropertyName("status")]
    public string Status { get; set; } = "ok";
}
