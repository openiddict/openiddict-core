using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authentication;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Exposes the default values used by the OpenIddict validation handler.
    /// </summary>
    public static class OpenIddictValidationDefaults
    {
        /// <summary>
        /// Default value for <see cref="AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = OAuthValidationDefaults.AuthenticationScheme;
    }
}
