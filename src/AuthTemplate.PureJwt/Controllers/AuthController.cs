using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using AuthTemplate.PureJwt.Models.Auth;
using AuthTemplate.Data.Entities.PureIdentity;
using AuthTemplate.Data;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using AuthTemplate.PureJwt.Options;
using Microsoft.Extensions.Options;

namespace AuthTemplate.PureJwt.Controllers;
[ApiController]
public class AuthController(PureDbContext DbContext, ILogger<AuthController> Logger, IOptionsSnapshot<JwtSettings> JwtOptions) : ControllerBase
{
    private readonly JwtSettings _jwtSettings = JwtOptions.Value;

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
            NormalizedUserName = model.Email.ToLowerInvariant(),
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

        var user = await DbContext.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail);

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

        var token = GenerateJwtToken(user!);
        return Ok(new { token });
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity([new Claim("id", "1")]),
            Expires = DateTime.UtcNow.AddHours(1),
            //Claims = claims,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return new JwtSecurityTokenHandler().WriteToken(token);
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
