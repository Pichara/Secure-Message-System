using SecureMessageBackend.Models;

namespace SecureMessageBackend.Middleware;

public class BodySizeLimitMiddleware
{
    private readonly RequestDelegate _next;

    public BodySizeLimitMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Only check body size for POST requests
        if (context.Request.Method == "POST")
        {
            context.Request.EnableBuffering();

            // Read the body to check size
            using var reader = new StreamReader(
                context.Request.Body,
                leaveOpen: true);
            var body = await reader.ReadToEndAsync();

            if (body.Length > Constants.MaxBodyBytes)
            {
                context.Response.StatusCode = 413;
                await context.Response.WriteAsJsonAsync(new { error = "payload_too_large" });
                return;
            }

            // Reset the stream position so it can be read again
            context.Request.Body.Position = 0;
        }

        await _next(context);
    }
}

public static class BodySizeLimitMiddlewareExtensions
{
    public static IApplicationBuilder UseBodySizeLimit(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<BodySizeLimitMiddleware>();
    }
}
