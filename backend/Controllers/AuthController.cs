using Microsoft.AspNetCore.Mvc;
using SecureMessageBackend.Models;
using SecureMessageBackend.Repositories;
using SecureMessageBackend.Services;

namespace SecureMessageBackend.Controllers;

[ApiController]
[Route("api")]
public class AuthController : ControllerBase
{
    private readonly UserRepository _userRepository;
    private readonly PasswordService _passwordService;
    private readonly TokenService _tokenService;

    public AuthController(
        UserRepository userRepository,
        PasswordService passwordService,
        TokenService tokenService)
    {
        _userRepository = userRepository;
        _passwordService = passwordService;
        _tokenService = tokenService;
    }

    /// <summary>
    /// Register a new user
    /// POST /api/register
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Validate required fields
        if (string.IsNullOrEmpty(request.Username) ||
            string.IsNullOrEmpty(request.Password) ||
            string.IsNullOrEmpty(request.PublicKey) ||
            string.IsNullOrEmpty(request.EncryptedPrivateKey))
        {
            return BadRequest(new ErrorResponse { Error = "missing_fields" });
        }

        // Validate username
        if (!_passwordService.IsValidUsername(request.Username))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_username" });
        }

        // Validate password
        var (isValid, errorMessage) = _passwordService.ValidatePassword(request.Password);
        if (!isValid)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "invalid_password",
                Message = errorMessage
            });
        }

        // Validate field lengths
        if (!_passwordService.IsFieldLengthValid(request.PublicKey, Constants.MaxPublicKeyLen) ||
            !_passwordService.IsFieldLengthValid(request.EncryptedPrivateKey, Constants.MaxEncryptedPrivateKeyLen))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_fields" });
        }

        // Check if user already exists
        if (await _userRepository.ExistsAsync(request.Username))
        {
            return BadRequest(new ErrorResponse { Error = "registration_failed" });
        }

        // Hash password and create user
        string passwordHash = _passwordService.HashPassword(request.Password);
        await _userRepository.CreateAsync(
            request.Username,
            passwordHash,
            request.PublicKey,
            request.EncryptedPrivateKey,
            Constants.UserRole
        );

        return StatusCode(201, new StatusResponse { Status = "registered" });
    }

    /// <summary>
    /// Login user
    /// POST /api/login
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // Validate required fields
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new ErrorResponse { Error = "missing_fields" });
        }

        // Get user
        var user = await _userRepository.GetByUsernameAsync(request.Username);
        if (user == null)
        {
            return Unauthorized(new ErrorResponse { Error = "invalid_credentials" });
        }

        // Verify password
        if (!_passwordService.VerifyPassword(user.PasswordHash, request.Password))
        {
            return Unauthorized(new ErrorResponse { Error = "invalid_credentials" });
        }

        // Create token
        string token = _tokenService.CreateToken(user.Username);

        return Ok(new LoginResponse
        {
            Token = token,
            ExpiresIn = (int)Constants.TokenTtl.TotalSeconds,
            Role = user.Role
        });
    }

    /// <summary>
    /// Logout user
    /// POST /api/logout
    /// </summary>
    [HttpPost("logout")]
    public IActionResult Logout()
    {
        string? token = ExtractBearerToken();
        if (string.IsNullOrEmpty(token))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        bool invalidated = _tokenService.InvalidateToken(token);
        if (!invalidated)
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        return Ok(new StatusResponse { Status = "logged_out" });
    }

    /// <summary>
    /// Get current user info
    /// GET /api/me
    /// </summary>
    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        string? username = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        var user = await _userRepository.GetByUsernameAsync(username);
        if (user == null)
        {
            return NotFound(new ErrorResponse { Error = "user_not_found" });
        }

        return Ok(new MeResponse
        {
            Username = user.Username,
            PublicKey = user.PublicKey,
            EncryptedPrivateKey = user.EncryptedPrivateKey,
            Role = user.Role
        });
    }

    /// <summary>
    /// Get public key by username
    /// GET /api/users/{username}/public-key
    /// </summary>
    [HttpGet("users/{username}/public-key")]
    public async Task<IActionResult> GetPublicKey(string username)
    {
        // Require authentication
        string? authUsername = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(authUsername))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        if (!_passwordService.IsValidUsername(username))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_username" });
        }

        var user = await _userRepository.GetByUsernameAsync(username);
        if (user == null)
        {
            return NotFound(new ErrorResponse { Error = "user_not_found" });
        }

        return Ok(new PublicKeyResponse
        {
            Username = user.Username,
            PublicKey = user.PublicKey
        });
    }

    /// <summary>
    /// List all usernames (admin only)
    /// GET /api/admin/users
    /// </summary>
    [HttpGet("admin/users")]
    public async Task<IActionResult> AdminListUsers()
    {
        string? username = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        var user = await _userRepository.GetByUsernameAsync(username);
        if (user == null || user.Role != Constants.AdminRole)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new ErrorResponse { Error = "forbidden" });
        }

        var usernames = await _userRepository.GetAllUsernamesAsync();
        return Ok(new UsersListResponse
        {
            Users = usernames.Select(u => new UserListItem { Username = u }).ToList()
        });
    }

    /// <summary>
    /// Delete a user account (admin only)
    /// DELETE /api/admin/users/{username}
    /// </summary>
    [HttpDelete("admin/users/{username}")]
    public async Task<IActionResult> AdminDeleteUser(string username)
    {
        string? authUsername = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(authUsername))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        var adminUser = await _userRepository.GetByUsernameAsync(authUsername);
        if (adminUser == null || adminUser.Role != Constants.AdminRole)
        {
            return StatusCode(StatusCodes.Status403Forbidden, new ErrorResponse { Error = "forbidden" });
        }

        if (!_passwordService.IsValidUsername(username))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_username" });
        }

        if (string.Equals(authUsername, username, StringComparison.Ordinal))
        {
            return BadRequest(new ErrorResponse
            {
                Error = "cannot_delete_self",
                Message = "Admins cannot delete their own account."
            });
        }

        var targetUser = await _userRepository.GetByUsernameAsync(username);
        if (targetUser == null)
        {
            return NotFound(new ErrorResponse { Error = "user_not_found" });
        }

        if (targetUser.Role == Constants.AdminRole)
        {
            return BadRequest(new ErrorResponse
            {
                Error = "cannot_delete_admin",
                Message = "Admin accounts cannot be deleted."
            });
        }

        bool deleted = await _userRepository.DeleteByUsernameAsync(username);
        if (!deleted)
        {
            return NotFound(new ErrorResponse { Error = "user_not_found" });
        }

        _tokenService.InvalidateTokensForUser(username);
        return Ok(new StatusResponse { Status = "deleted" });
    }

    private string? GetAuthenticatedUsername()
    {
        string? token = ExtractBearerToken();
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }
        return _tokenService.ValidateToken(token);
    }

    private string? ExtractBearerToken()
    {
        string? auth = Request.Headers["Authorization"];
        if (string.IsNullOrEmpty(auth))
        {
            return null;
        }

        const string prefix = "Bearer ";
        if (!auth.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return auth.Substring(prefix.Length);
    }
}
