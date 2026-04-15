namespace SecureMessageBackend.Models;

public class ErrorResponse
{
    public string Error { get; set; } = string.Empty;
    public string? Message { get; set; }
}

public class LoginResponse
{
    public string Token { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public string Role { get; set; } = string.Empty;
}

public class MeResponse
{
    public string Username { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string EncryptedPrivateKey { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

public class ContactResponse
{
    public string Alias { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
}

public class UsersListResponse
{
    public List<UserListItem> Users { get; set; } = new();
}

public class UserListItem
{
    public string Username { get; set; } = string.Empty;
}

public class PublicKeyResponse
{
    public string Username { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
}

public class MessageStoredResponse
{
    public string Status { get; set; } = "stored";
    public int Id { get; set; }
}

public class StatusResponse
{
    public string Status { get; set; } = string.Empty;
}

public class HealthResponse
{
    public string Status { get; set; } = "ok";
}
