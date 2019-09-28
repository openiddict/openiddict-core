using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace OpenIddict.Sandbox.AspNetCore.Server.ViewModels.Manage;

public class ManageLoginsViewModel
{
    public IList<UserLoginInfo> CurrentLogins { get; set; }

    public IList<AuthenticationScheme> OtherLogins { get; set; }
}
