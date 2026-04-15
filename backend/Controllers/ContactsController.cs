using Microsoft.AspNetCore.Mvc;
using SecureMessageBackend.Models;
using SecureMessageBackend.Repositories;
using SecureMessageBackend.Services;

namespace SecureMessageBackend.Controllers;

[ApiController]
[Route("api")]
public class ContactsController : ControllerBase
{
    private readonly UserRepository _userRepository;
    private readonly ContactRepository _contactRepository;
    private readonly PasswordService _passwordService;
    private readonly TokenService _tokenService;

    public ContactsController(
        UserRepository userRepository,
        ContactRepository contactRepository,
        PasswordService passwordService,
        TokenService tokenService)
    {
        _userRepository = userRepository;
        _contactRepository = contactRepository;
        _passwordService = passwordService;
        _tokenService = tokenService;
    }

    /// <summary>
    /// List contacts for current user
    /// GET /api/contacts
    /// </summary>
    [HttpGet("contacts")]
    public async Task<IActionResult> ListContacts()
    {
        string? username = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        var owner = await _userRepository.GetByUsernameAsync(username);
        if (owner == null)
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        var contacts = await _contactRepository.GetForUserAsync(owner.Id);
        return Ok(contacts.Select(c => new ContactResponse
        {
            Alias = c.Alias,
            Username = c.Username
        }).ToList());
    }

    /// <summary>
    /// Save or update a contact
    /// POST /api/contacts
    /// </summary>
    [HttpPost("contacts")]
    public async Task<IActionResult> SaveContact([FromBody] SaveContactRequest request)
    {
        string? username = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        // Validate required fields
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Alias))
        {
            return BadRequest(new ErrorResponse { Error = "missing_fields" });
        }

        // Validate username and alias
        if (!_passwordService.IsValidUsername(request.Username) ||
            !_passwordService.IsValidUsername(request.Alias))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_username" });
        }

        var owner = await _userRepository.GetByUsernameAsync(username);
        var contactUser = await _userRepository.GetByUsernameAsync(request.Username);

        if (owner == null)
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        if (contactUser == null)
        {
            return NotFound(new ErrorResponse { Error = "user_not_found" });
        }

        if (owner.Id == contactUser.Id)
        {
            return BadRequest(new ErrorResponse { Error = "invalid_contact" });
        }

        await _contactRepository.SaveAsync(owner.Id, request.Alias, contactUser.Id);
        return StatusCode(201, new StatusResponse { Status = "saved" });
    }

    /// <summary>
    /// Delete a contact by alias
    /// DELETE /api/contacts/{alias}
    /// </summary>
    [HttpDelete("contacts/{alias}")]
    public async Task<IActionResult> DeleteContact(string alias)
    {
        string? username = GetAuthenticatedUsername();
        if (string.IsNullOrEmpty(username))
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        if (!_passwordService.IsValidUsername(alias))
        {
            return BadRequest(new ErrorResponse { Error = "invalid_username" });
        }

        var owner = await _userRepository.GetByUsernameAsync(username);
        if (owner == null)
        {
            return Unauthorized(new ErrorResponse { Error = "unauthorized" });
        }

        bool deleted = await _contactRepository.DeleteAsync(owner.Id, alias);
        if (!deleted)
        {
            return NotFound(new ErrorResponse { Error = "alias_not_found" });
        }

        return Ok(new StatusResponse { Status = "removed" });
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
