using SecureMessageBackend.Services;

namespace SecureMessageBackend.Middleware;

public class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly RateLimiterService _rateLimiter;

    public RateLimitMiddleware(RequestDelegate next, RateLimiterService rateLimiter)
    {
        _next = next;
        _rateLimiter = rateLimiter;
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
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new { error = "rate_limited" });
                return;
            }

            var username = context.Request.Form["username"].ToString();
            if (string.IsNullOrEmpty(username))
            {
                // Try reading from JSON body
                try
                {
                    context.Request.EnableBuffering();
                    using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
                    var body = await reader.ReadToEndAsync();
                    context.Request.Body.Position = 0;

                    var json = System.Text.Json.JsonDocument.Parse(body);
                    if (json.RootElement.TryGetProperty("username", out var usernameElement))
                    {
                        username = usernameElement.GetString() ?? string.Empty;
                    }
                }
                catch { }
            }

            if (!string.IsNullOrEmpty(username) && !_rateLimiter.AllowLoginUsername(username))
            {
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
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new { error = "rate_limited" });
                return;
            }

            var username = context.Request.Form["username"].ToString();
            if (string.IsNullOrEmpty(username))
            {
                // Try reading from JSON body
                try
                {
                    context.Request.EnableBuffering();
                    using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
                    var body = await reader.ReadToEndAsync();
                    context.Request.Body.Position = 0;

                    var json = System.Text.Json.JsonDocument.Parse(body);
                    if (json.RootElement.TryGetProperty("username", out var usernameElement))
                    {
                        username = usernameElement.GetString() ?? string.Empty;
                    }
                }
                catch { }
            }

            if (!string.IsNullOrEmpty(username) && !_rateLimiter.AllowRegisterUsername(username))
            {
                context.Response.StatusCode = 429;
                await context.Response.WriteAsJsonAsync(new { error = "rate_limited" });
                return;
            }
        }

        await _next(context);
    }

    private string GetClientIp(HttpContext context)
    {
        // Check for forwarded headers (proxy scenario)
        if (context.Request.Headers.ContainsKey("X-Forwarded-For"))
        {
            var forwarded = context.Request.Headers["X-Forwarded-For"].ToString();
            var ips = forwarded.Split(',');
            if (ips.Length > 0)
            {
                return ips[0].Trim();
            }
        }

        // Fall back to remote IP
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

public static class RateLimitMiddlewareExtensions
{
    public static IApplicationBuilder UseRateLimit(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RateLimitMiddleware>();
    }
}
