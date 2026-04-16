using SecureMessageBackend.Middleware;
using SecureMessageBackend.Repositories;
using SecureMessageBackend.Services;

var builder = WebApplication.CreateBuilder(args);
var contentRoot = AppContext.BaseDirectory;

// Add services
builder.Services.AddControllers();

// Register application services
builder.Services.AddSingleton<DatabaseService>();
builder.Services.AddSingleton<PasswordService>();
builder.Services.AddSingleton<TokenService>();
builder.Services.AddSingleton<RateLimiterService>();
builder.Services.AddScoped<UserRepository>();
builder.Services.AddScoped<ContactRepository>();
builder.Services.AddScoped<MessageRepository>();

// Add CORS
builder.Services.AddCors();

var app = builder.Build();

// Configure middleware
app.UseMiddleware<BodySizeLimitMiddleware>();
app.UseMiddleware<RateLimitMiddleware>();
app.UseMiddleware<CorsMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();

// Map routes
app.MapControllers();

// Health check endpoint
app.MapGet("/health", () => Results.Json(new { status = "ok" }))
   .WithName("HealthCheck");

// OpenAPI spec endpoint
app.MapGet("/openapi.json", () =>
{
    var spec = System.IO.File.ReadAllText(Path.Combine(contentRoot, "OpenApiSpec.json"));
    return Results.Text(spec, "application/json");
})
.WithName("OpenApiSpec");

// API docs endpoint
app.MapGet("/api/docs", () =>
{
    var html = System.IO.File.ReadAllText(Path.Combine(contentRoot, "Docs.html"));
    return Results.Text(html, "text/html");
})
.WithName("ApiDocs");

// Initialize database
using (var scope = app.Services.CreateScope())
{
    var dbService = scope.ServiceProvider.GetRequiredService<DatabaseService>();
    await dbService.InitializeAsync();
}

var port = Environment.GetEnvironmentVariable("PORT") ?? "8080";
var urls = $"http://0.0.0.0:{port}";

Console.WriteLine($"Secure Message Backend listening on {urls}");

app.Run(urls);
