using AuthTemplate.Data.Entities.AspNetCoreIdentity;
using AuthTemplate.IdentityCookie.Models.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace AuthTemplate.IdentityCookie.Controllers;
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
    public async Task<ActionResult> Login([FromBody] LoginModel model)
    {
        var normalizedEmail = model.Email.ToUpperInvariant();
        var user = await UserManager
            .Users
            .SingleOrDefaultAsync(x => x.EmailConfirmed && x.NormalizedEmail == normalizedEmail)
            ;

        if (user == null)
        {
            ModelState.AddModelError(string.Empty, "LOGIN_FAILED");
            return ValidationProblem(ModelState);
        }

        var signInResult = await SignInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);
        if (!signInResult.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "LOGIN_FAILED");
            return ValidationProblem(ModelState);
        }

        var userPrincipal = await SignInManager.CreateUserPrincipalAsync(user);
        await HttpContext.SignInAsync(userPrincipal);

        return NoContent();
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
