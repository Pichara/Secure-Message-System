using System.Text.Json.Serialization;

namespace SecureMessageBackend.Models;

public class RegisterRequest
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = string.Empty;

    [JsonPropertyName("encrypted_private_key")]
    public string EncryptedPrivateKey { get; set; } = string.Empty;
}

public class LoginRequest
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;
}

public class SaveContactRequest
{
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("alias")]
    public string Alias { get; set; } = string.Empty;
}

public class SendMessageRequest
{
    [JsonPropertyName("recipient")]
    public string Recipient { get; set; } = string.Empty;

    [JsonPropertyName("encrypted_key")]
    public string EncryptedKey { get; set; } = string.Empty;

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;

    [JsonPropertyName("iv")]
    public string Iv { get; set; } = string.Empty;
}
