using AuthTemplate.Data.Entities.AspNetCoreIdentity;
using AuthTemplate.IdentityJwt.Models.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthTemplate.IdentityJwt.Controllers;
[ApiController]
public class AuthController(
    UserManager<ApplicationUser> UserManager,
    SignInManager<ApplicationUser> SignInManager
        ) : ControllerBase
{
    [HttpPost("api/v1/Auth/Register")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult> Register(
       [FromBody] RegisterModel model
       )
    {
        var validator = new PasswordValidator<ApplicationUser>();

        var newUser = new ApplicationUser
        {
            Id = Guid.NewGuid(),
            Email = model.Email,
            UserName = model.Email,
        };

        var checkPassword = await validator.ValidateAsync(UserManager, newUser, model.Password);

        if (!checkPassword.Succeeded)
        {
            ModelState.AddModelError<RegisterModel>(
                x => x.Password, string.Join("\n", checkPassword.Errors.Select(x => x.Description)));
            return ValidationProblem(ModelState);
        }

        await UserManager.CreateAsync(newUser);
        await UserManager.AddPasswordAsync(newUser, model.Password);
        var token = string.Empty;
        token = await UserManager.GenerateEmailConfirmationTokenAsync(newUser);

        return Ok(token);
    }

    [HttpPost("api/v1/Auth/Login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        var user = await UserManager.FindByNameAsync(model.Email);
        if (user != null && await UserManager.CheckPasswordAsync(user, model.Password))
        {             
            var token = GenerateJwtToken(user!);
            return Ok(new { token });
        }
        ModelState.AddModelError(string.Empty, "LOGIN_FAILED");
        return ValidationProblem(ModelState);
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

    /// <summary>
    /// unescape token before sending
    /// </summary>
    /// <param name="model"></param>
    /// <returns></returns>
    [HttpPost("api/v1/Auth/ValidateToken")]
    public async Task<ActionResult> ValidateToken(
        [FromBody] TokenModel model
        )
    {
        var normalizedMail = model.Email.ToUpperInvariant();
        var user = await UserManager
            .Users
            .SingleOrDefaultAsync(x => !x.EmailConfirmed && x.NormalizedEmail == normalizedMail);

        if (user == null)
        {
            ModelState.AddModelError<TokenModel>(x => x.Token, "INVALID_TOKEN");
            return ValidationProblem(ModelState);
        }

        var check = await UserManager.ConfirmEmailAsync(user, model.Token);
        if (!check.Succeeded)
        {
            ModelState.AddModelError<TokenModel>(x => x.Token, "INVALID_TOKEN");
            return ValidationProblem(ModelState);
        }

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
