/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Validation.AspNetCore
{
    /// <summary>
    /// Exposes the current validation transaction to the ASP.NET Core host.
    /// </summary>
    public class OpenIddictValidationAspNetCoreFeature
    {
        /// <summary>
        /// Gets or sets the validation transaction that encapsulates all specific
        /// information about an individual OpenID Connect validation request.
        /// </summary>
        public OpenIddictValidationTransaction Transaction { get; set; }
    }
}
