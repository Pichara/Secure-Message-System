namespace SecureMessageBackend.Models;

public class RegisterRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string EncryptedPrivateKey { get; set; } = string.Empty;
}

public class LoginRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class SaveContactRequest
{
    public string Username { get; set; } = string.Empty;
    public string Alias { get; set; } = string.Empty;
}

public class SendMessageRequest
{
    public string Recipient { get; set; } = string.Empty;
    public string EncryptedKey { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string Iv { get; set; } = string.Empty;
}
