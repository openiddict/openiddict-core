using System.ComponentModel.DataAnnotations;

namespace OpenIddict.Sandbox.AspNetCore.Server.ViewModels.Manage;

public class AddPhoneNumberViewModel
{
    [Required]
    [Phone]
    [Display(Name = "Phone number")]
    public string PhoneNumber { get; set; }
}
