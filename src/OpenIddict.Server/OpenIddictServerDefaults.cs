using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;

namespace OpenIddict.Server
{
    /// <summary>
    /// Exposes the default values used by the OpenIddict server handler.
    /// </summary>
    public static class OpenIddictServerDefaults
    {
        /// <summary>
        /// Default value for <see cref="AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = OpenIdConnectServerDefaults.AuthenticationScheme;
    }
}
