namespace SecureMessageBackend.Models;

public static class Constants
{
    public const int MaxBodyBytes = 256 * 1024 * 1024;
    public const int MinUsernameLen = 3;
    public const int MaxUsernameLen = 32;
    public const int MinPasswordLen = 8;
    public const int MaxPasswordLen = 128;
    public const int MaxPublicKeyLen = 512;
    public const int MaxEncryptedPrivateKeyLen = 8192;
    public const int MaxEncryptedKeyLen = 4096;
    public const int MaxCiphertextLen = 200 * 1024 * 1024;
    public const int MaxIvLen = 128;

    public const string UserRole = "user";
    public const string AdminRole = "admin";
    public const string BootstrapAdminPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    public const string BootstrapAdminEncryptedPrivateKey = "{\"ciphertext\":\"\",\"salt\":\"\",\"nonce\":\"\"}";

    public static TimeSpan TokenTtl = TimeSpan.FromHours(1);
    public static TimeSpan TokenCleanupInterval = TimeSpan.FromMinutes(5);
}
