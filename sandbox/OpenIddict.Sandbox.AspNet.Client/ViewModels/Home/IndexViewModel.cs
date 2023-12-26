using System.Collections.Generic;
using System.Web.ModelBinding;
using OpenIddict.Client;

namespace OpenIddict.Sandbox.AspNet.Client.ViewModels.Home;

public class IndexViewModel
{
    [BindNever]
    public string Message { get; set; }

    [BindNever]
    public IEnumerable<OpenIddictClientRegistration> Providers { get; set; }
}
