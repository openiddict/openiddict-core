using Microsoft.AspNetCore.Mvc.Rendering;

namespace OpenIddict.Sandbox.AspNetCore.Server.ViewModels.Manage;

public class ConfigureTwoFactorViewModel
{
    public string SelectedProvider { get; set; }

    public ICollection<SelectListItem> Providers { get; set; }
}
