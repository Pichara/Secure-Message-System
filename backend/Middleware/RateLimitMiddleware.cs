// Security hardening updates by Rodrigo P Gomes.
using SecureMessageBackend.Services;
using System.Net;
using System.Text.Json;

namespace SecureMessageBackend.Middleware;

public class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly RateLimiterService _rateLimiter;
    private readonly ILogger<RateLimitMiddleware> _logger;
    private readonly bool _trustProxyHeaders;

    public RateLimitMiddleware(
        RequestDelegate next,
        RateLimiterService rateLimiter,
        IConfiguration configuration,
        ILogger<RateLimitMiddleware> logger)
    {
        _next = next;
        _rateLimiter = rateLimiter;
        _logger = logger;
        _trustProxyHeaders = bool.TryParse(configuration["TRUST_PROXY_HEADERS"], out var enabled) && enabled;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;

        // Apply rate limiting to login endpoint
        if (path == "/api/login")
        {
            var ip = GetClientIp(context);
            if (!_rateLimiter.AllowLoginIp(ip))
            {
                _logger.LogWarning("Rate limit exceeded for login IP {ClientIp}", ip);
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new { error = "rate_limited" });
                return;
            }

            var username = await TryGetUsernameAsync(context);

            if (!string.IsNullOrEmpty(username) && !_rateLimiter.AllowLoginUsername(username))
            {
                _logger.LogWarning("Rate limit exceeded for login username {Username}", username);
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new { error = "rate_limited" });
                return;
            }
        }

        // Apply rate limiting to register endpoint
        if (path == "/api/register")
        {
            var ip = GetClientIp(context);
            if (!_rateLimiter.AllowRegisterIp(ip))
            {
                _logger.LogWarning("Rate limit exceeded for register IP {ClientIp}", ip);
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new { error = "rate_limited" });
                return;
            }

            var username = await TryGetUsernameAsync(context);

            if (!string.IsNullOrEmpty(username) && !_rateLimiter.AllowRegisterUsername(username))
            {
                _logger.LogWarning("Rate limit exceeded for register username {Username}", username);
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new { error = "rate_limited" });
                return;
            }
        }

        await _next(context);
    }

    private static async Task<string> TryGetUsernameAsync(HttpContext context)
    {
        if (context.Request.HasFormContentType)
        {
            try
            {
                var form = await context.Request.ReadFormAsync();
                var username = form["username"].ToString();
                if (!string.IsNullOrWhiteSpace(username))
                {
                    return username;
                }
            }
            catch
            {
                // Ignore malformed form bodies and fall back to JSON parsing.
            }
        }

        try
        {
            context.Request.EnableBuffering();
            context.Request.Body.Position = 0;

            using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;

            if (string.IsNullOrWhiteSpace(body))
            {
                return string.Empty;
            }

            using var json = JsonDocument.Parse(body);
            if (json.RootElement.TryGetProperty("username", out var usernameElement))
            {
                return usernameElement.GetString() ?? string.Empty;
            }
        }
        catch
        {
            context.Request.Body.Position = 0;
        }

        return string.Empty;
    }

    private string GetClientIp(HttpContext context)
    {
        if (_trustProxyHeaders && context.Request.Headers.ContainsKey("X-Forwarded-For"))
        {
            var forwarded = context.Request.Headers["X-Forwarded-For"].ToString();
            var ips = forwarded.Split(',');
            if (ips.Length > 0)
            {
                var candidate = ips[0].Trim();
                if (!string.IsNullOrWhiteSpace(candidate))
                {
                    return candidate;
                }
            }
        }

        var remoteIp = context.Connection.RemoteIpAddress;
        if (remoteIp == null)
        {
            return "unknown";
        }

        if (IPAddress.IsLoopback(remoteIp))
        {
            return "loopback";
        }

        return remoteIp.ToString();
    }
}

public static class RateLimitMiddlewareExtensions
{
    public static IApplicationBuilder UseRateLimit(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RateLimitMiddleware>();
    }
}
