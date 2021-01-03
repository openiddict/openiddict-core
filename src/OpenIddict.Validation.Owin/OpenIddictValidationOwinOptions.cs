/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Owin.Security;

namespace OpenIddict.Validation.Owin
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict OWIN validation integration.
    /// </summary>
    public class OpenIddictValidationOwinOptions : AuthenticationOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationOwinOptions"/> class.
        /// </summary>
        public OpenIddictValidationOwinOptions()
            : base(OpenIddictValidationOwinDefaults.AuthenticationType)
            => AuthenticationMode = AuthenticationMode.Passive;

        /// <summary>
        /// Gets or sets the optional "realm" value returned to the caller as part of the WWW-Authenticate header.
        /// </summary>
        public string? Realm { get; set; }
    }
}
