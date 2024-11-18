namespace AuthTemplate.Data.Entities.PureIdentity;
public class ApplicationUser
{
    public Guid Id { get; set; }
    public string Email { get; set; } = null!;
    public string NormalizedEmail { get; set; } = null!;

    public string UserName { get; set; } = null!;
    public string NormalizedUserName { get; set; } = null!;

    public string PasswordHash { get; set; } = null!;
}
