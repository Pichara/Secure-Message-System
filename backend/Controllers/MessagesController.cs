using Microsoft.AspNetCore.Mvc;
using SecureMessageBackend.Models;
using SecureMessageBackend.Repositories;
using SecureMessageBackend.Services;

namespace SecureMessageBackend.Controllers;

[ApiController]
[Route("api")]
public class MessagesController : ControllerBase
{
    private readonly UserRepository _userRepository;
    private readonly MessageRepository _messageRepository;
    private readonly PasswordService _passwordService;
    private readonly TokenService _tokenService;

    public MessagesController(
        UserRepository userRepository,
        MessageRepository messageRepository,
        PasswordService passwordService,
        TokenService tokenService)
    {
        _userRepository = userRepository;
        _messageRepository = messageRepository;
        _passwordService = passwordService;
        _tokenService = tokenService;
    }

    /// <summary>
    /// Send a message
    /// POST /api/messages
    /// </summary>
    [HttpPost("messages")]
    public async Task<IActionResult> SendMessage([FromBody] SendMessageRequest request)
    {
        string? username = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        // Validate required fields
        if (string.IsNullOrEmpty(request.Recipient) ||
            string.IsNullOrEmpty(request.EncryptedKey) ||
            string.IsNullOrEmpty(request.Ciphertext) ||
            string.IsNullOrEmpty(request.Iv))
        {
            return BadRequest(new ErrorResponse { Error = "missing_fields" });
        }

        // Validate username
        if (!_passwordService.IsValidUsername(request.Recipient))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_username" });
        }

        // Validate field lengths
        if (!_passwordService.IsFieldLengthValid(request.EncryptedKey, Constants.MaxEncryptedKeyLen) ||
            !_passwordService.IsFieldLengthValid(request.Ciphertext, Constants.MaxCiphertextLen) ||
            !_passwordService.IsFieldLengthValid(request.Iv, Constants.MaxIvLen))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_fields" });
        }

        var sender = await _userRepository.GetByUsernameAsync(username);
        var recipient = await _userRepository.GetByUsernameAsync(request.Recipient);

        if (sender == null || recipient == null)
        {
            return NotFound(new ErrorResponse { Error = "recipient_not_found" });
        }

        int messageId = await _messageRepository.CreateAsync(
            sender.Id,
            recipient.Id,
            request.EncryptedKey,
            request.Ciphertext,
            request.Iv
        );

        return StatusCode(201, new MessageStoredResponse
        {
            Status = "stored",
            Id = messageId
        });
    }

    /// <summary>
    /// List messages
    /// GET /api/messages?with={username}&limit={n}&order={asc|desc}&before_id={id}
    /// </summary>
    [HttpGet("messages")]
    public async Task<IActionResult> ListMessages(
        [FromQuery] string? with = null,
        [FromQuery] int? limit = null,
        [FromQuery] string? order = null,
        [FromQuery] int? beforeId = null)
    {
        string? username = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        var user = await _userRepository.GetByUsernameAsync(username);
        if (user == null)
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        // Parse and validate limit
        int effectiveLimit = 200;
        if (limit.HasValue && limit.Value > 0)
        {
            effectiveLimit = Math.Min(limit.Value, 200);
        }

        // Parse order
        string effectiveOrder = (order?.ToLower() == "desc") ? "desc" : "asc";

        var messages = await _messageRepository.GetForUserAsync(
            user.Id,
            with,
            beforeId,
            effectiveLimit,
            effectiveOrder
        );

        return Ok(messages);
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
