namespace SecureMessageBackend.Models;

public class DbContact
{
    public int Id { get; set; }
    public string Alias { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
}
