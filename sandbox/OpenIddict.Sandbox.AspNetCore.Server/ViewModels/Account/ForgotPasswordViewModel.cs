using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Sandbox.AspNetCore.Server.ViewModels.Account;

public class ForgotPasswordViewModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}
