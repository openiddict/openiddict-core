using System.ComponentModel.DataAnnotations;

namespace Mvc.Server.ViewModels.Account {
    public class ForgotPasswordViewModel {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
