using Microsoft.AspNetCore.Mvc.ModelBinding;
using OpenIddict.Client;

namespace OpenIddict.Sandbox.AspNetCore.Client.ViewModels.Home;

public class IndexViewModel
{
    [BindNever]
    public string Message { get; set; }

    [BindNever]
    public IEnumerable<OpenIddictClientRegistration> Providers { get; set; }
}
