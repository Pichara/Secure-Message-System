namespace SecureMessageBackend.Services;

public class RateLimiterService
{
    private readonly object _lock = new();
    private readonly Dictionary<string, RateLimitEntry> _entries = new();

    private class RateLimitEntry
    {
        public int Count { get; set; }
        public DateTime WindowStart { get; set; }
    }

    /// <summary>
    /// Checks if a request is allowed based on rate limiting rules
    /// </summary>
    /// <param name="key">The rate limit key (e.g., IP address or username)</param>
    /// <param name="limit">Maximum number of requests allowed</param>
    /// <param name="window">Time window for the limit</param>
    /// <returns>True if allowed, false if rate limited</returns>
    public bool Allow(string key, int limit, TimeSpan window)
    {
        var now = DateTime.UtcNow;

        lock (_lock)
        {
            if (!_entries.TryGetValue(key, out var entry))
            {
                entry = new RateLimitEntry
                {
                    Count = 0,
                    WindowStart = now
                };
                _entries[key] = entry;
            }

            // Check if we need to reset the window
            if (now - entry.WindowStart > window)
            {
                entry.Count = 0;
                entry.WindowStart = now;
            }

            entry.Count++;
            return entry.Count <= limit;
        }
    }

    /// <summary>
    /// Checks login IP rate limit (20 requests per 60 seconds)
    /// </summary>
    public bool AllowLoginIp(string ip)
    {
        return Allow($"login_ip:{ip}", 20, TimeSpan.FromSeconds(60));
    }

    /// <summary>
    /// Checks login username rate limit (10 requests per 60 seconds)
    /// </summary>
    public bool AllowLoginUsername(string username)
    {
        return Allow($"login_user:{username}", 10, TimeSpan.FromSeconds(60));
    }

    /// <summary>
    /// Checks register IP rate limit (30 requests per 60 seconds)
    /// </summary>
    public bool AllowRegisterIp(string ip)
    {
        return Allow($"register_ip:{ip}", 30, TimeSpan.FromSeconds(60));
    }

    /// <summary>
    /// Checks register username rate limit (5 requests per 60 seconds)
    /// </summary>
    public bool AllowRegisterUsername(string username)
    {
        return Allow($"register_user:{username}", 5, TimeSpan.FromSeconds(60));
    }
}
