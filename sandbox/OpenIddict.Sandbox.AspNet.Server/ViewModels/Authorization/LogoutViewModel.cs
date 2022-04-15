using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

namespace OpenIddict.Sandbox.AspNet.Server.ViewModels.Authorization
{
    [Bind(Exclude = nameof(Parameters))]
    public class AuthorizeViewModel
    {
        [Display(Name = "Application")]
        public string ApplicationName { get; set; }

        [Display(Name = "Scope")]
        public string Scope { get; set; }

        public IEnumerable<KeyValuePair<string, string>> Parameters { get; internal set; }
    }
}
