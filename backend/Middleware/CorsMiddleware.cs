// Security hardening updates by Rodrigo P Gomes.
namespace SecureMessageBackend.Middleware;

public class CorsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly bool _allowAll;
    private readonly HashSet<string> _allowedOrigins;
    private static readonly string[] DefaultAllowedOrigins =
    {
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:4173",
        "http://127.0.0.1:4173"
    };

    public CorsMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        var corsOrigin = configuration["CORS_ORIGIN"];

        if (string.Equals(corsOrigin, "*", StringComparison.Ordinal))
        {
            _allowAll = true;
            _allowedOrigins = new HashSet<string>();
        }
        else
        {
            _allowAll = false;
            _allowedOrigins = new HashSet<string>(
                string.IsNullOrWhiteSpace(corsOrigin)
                    ? DefaultAllowedOrigins
                    : corsOrigin.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                StringComparer.OrdinalIgnoreCase
            );
        }
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var origin = context.Request.Headers["Origin"].ToString();

        if (!string.IsNullOrEmpty(origin))
        {
            if (_allowAll)
            {
                context.Response.Headers["Access-Control-Allow-Origin"] = "*";
            }
            else if (_allowedOrigins.Contains(origin))
            {
                context.Response.Headers["Access-Control-Allow-Origin"] = origin;
                context.Response.Headers["Vary"] = "Origin";
            }
            else
            {
                // Origin not allowed
                context.Response.StatusCode = 403;
                await context.Response.WriteAsJsonAsync(new { error = "cors_denied" });
                return;
            }
        }

        context.Response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
        context.Response.Headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS";
        context.Response.Headers["Access-Control-Max-Age"] = "86400";

        // Handle preflight requests
        if (context.Request.Method == "OPTIONS")
        {
            context.Response.StatusCode = 204;
            return;
        }

        await _next(context);
    }
}

public static class CorsMiddlewareExtensions
{
    public static IApplicationBuilder UseCorsMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<CorsMiddleware>();
    }
}
