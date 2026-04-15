namespace SecureMessageBackend.Models;

public class DbUser
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string EncryptedPrivateKey { get; set; } = string.Empty;
    public string Role { get; set; } = Constants.UserRole;
    public DateTime CreatedAt { get; set; }
}
