using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using OpenIddict.Sandbox.AspNetCore.Server.Models;

namespace OpenIddict.Sandbox.AspNetCore.Server.Services;

public sealed class UserClaimsPrincipalFactory : UserClaimsPrincipalFactory<ApplicationUser>
{
    public UserClaimsPrincipalFactory(
        UserManager<ApplicationUser> userManager,
        IOptions<IdentityOptions> optionsAccessor)
        : base(userManager, optionsAccessor)
    {
    }

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        var identity = await base.GenerateClaimsAsync(user);

        // Generate and attach a unique login identifier to the claims identity: this value will
        // be used by the authorization controller to infer a unique identifier representing the
        // current user session and bind the tokens issued by OpenIddict to a specific session.
        //
        // Note: this method is also called when the application cookie is refreshed: to ensure
        // the login identifier is preserved, a custom OnValidateIdentity event handler is used
        // to copy the login identifier from the existing principal to the refreshed instance.
        identity.AddClaim(new Claim("login_id", Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(256 / 8))));

        return identity;
    }
}
