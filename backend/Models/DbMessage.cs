namespace SecureMessageBackend.Models;

public class DbMessage
{
    public int Id { get; set; }
    public string Sender { get; set; } = string.Empty;
    public string Recipient { get; set; } = string.Empty;
    public string EncryptedKey { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string Iv { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}
