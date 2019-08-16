using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Mvc.Server.ViewModels.Authorization
{
    public class AuthorizeViewModel
    {
        [Display(Name = "Application")]
        public string ApplicationName { get; set; }

        [BindNever]
        public IEnumerable<KeyValuePair<string, string>> Parameters { get; set; }

        [Display(Name = "Scope")]
        public string Scope { get; set; }
    }
}
