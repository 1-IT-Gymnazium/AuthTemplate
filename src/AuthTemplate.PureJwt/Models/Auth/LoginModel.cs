using System.ComponentModel.DataAnnotations;

namespace AuthTemplate.PureJwt.Models.Auth;

public class LoginModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = null!;
    [Required]
    public string Password { get; set; } = null!;
}
