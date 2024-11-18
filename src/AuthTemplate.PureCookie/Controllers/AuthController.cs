using AuthTemplate.Data;
using AuthTemplate.Data.Entities.PureIdentity;
using AuthTemplate.PureCookie.Models.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AuthTemplate.PureCookie.Controllers;
[ApiController]
public class AuthController(
    PureDbContext DbContext,
    ILogger<AuthController> Logger) : ControllerBase
{
    [HttpPost("api/v1/Auth/Register")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> Register(
       [FromBody] RegisterModel model
       )
    {

        if (string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
            return ValidationProblem();

        if (DbContext.Users.Any(u => u.NormalizedEmail == model.Email.ToUpperInvariant()))
            return ValidationProblem();

        var newUser = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = model.Email,
            NormalizedEmail = model.Email.ToUpperInvariant(),
            UserName = model.Email,
            // AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            PasswordHash = model.Password,
        };

        DbContext.Users.Add(newUser);
        await DbContext.SaveChangesAsync();

        return Ok();
    }

    [HttpPost("api/v1/Auth/Login")]
    public async Task<ActionResult> Login([FromBody] LoginModel model)
    {
        var normalizedEmail = model.Email.ToUpperInvariant();

        var user = await DbContext.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == model.Email);

        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "LOGIN_FAILED");
            return ValidationProblem(ModelState);
        }

        if (user.PasswordHash != model.Password)
        {
            ModelState.AddModelError(string.Empty, "LOGIN_FAILED");
            return ValidationProblem(ModelState);
        }

        var claims = new List<Claim>
        {
            new (ClaimTypes.Name, user!.Email),
            new (ClaimTypes.NameIdentifier, user!.Id.ToString()),
        };

        var claimsIdentity = new ClaimsIdentity(
           claims, CookieAuthenticationDefaults.AuthenticationScheme);

        await HttpContext.SignInAsync(new ClaimsPrincipal(claimsIdentity));

        return NoContent();
    }

    [Authorize]
    [HttpGet("api/v1/Auth/UserInfo")]
    public async Task<ActionResult<string>> UserInfo()
    {
        if (User.Identity == null || !User.Identity.IsAuthenticated)
        {
            throw new InvalidOperationException("user not logged in");
        }
        var name = User.Claims.First(x => x.Type == ClaimTypes.Name).Value;

        if (User.Identity == null || !User.Identity.IsAuthenticated)
        {
            throw new InvalidOperationException("user not logged in");
        }
        var idString = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
        var guid = Guid.Parse(idString);
        return Ok($"{name} ({guid})");
    }

    [Authorize]
    [HttpPost("api/v1/Auth/Logout")]
    public async Task<ActionResult> Logout()
    {
        await HttpContext.SignOutAsync();
        return NoContent();
    }
}
