using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Builder;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Exposes the default values used by the OpenIddict validation handler.
    /// </summary>
    public static class OpenIddictValidationDefaults
    {
        /// <summary>
        /// Default value for <see cref="AuthenticationOptions.AuthenticationScheme"/>.
        /// </summary>
        public const string AuthenticationScheme = OAuthValidationDefaults.AuthenticationScheme;
    }
}
