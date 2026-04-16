using System.Text.Json.Serialization;

namespace SecureMessageBackend.Models;

public class DbMessage
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("sender")]
    public string Sender { get; set; } = string.Empty;

    [JsonPropertyName("recipient")]
    public string Recipient { get; set; } = string.Empty;

    [JsonPropertyName("encrypted_key")]
    public string EncryptedKey { get; set; } = string.Empty;

    [JsonPropertyName("ciphertext")]
    public string Ciphertext { get; set; } = string.Empty;

    [JsonPropertyName("iv")]
    public string Iv { get; set; } = string.Empty;

    [JsonPropertyName("created_at")]
    public DateTime CreatedAt { get; set; }
}
