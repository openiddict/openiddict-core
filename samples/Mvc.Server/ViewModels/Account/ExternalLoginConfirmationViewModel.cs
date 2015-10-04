using System.ComponentModel.DataAnnotations;

namespace Mvc.Server.ViewModels.Account {
    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
