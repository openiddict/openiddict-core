/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using AspNet.Security.OAuth.Validation;

namespace OpenIddict.Validation
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict validation handler.
    /// </summary>
    public class OpenIddictValidationOptions : OAuthValidationOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationOptions"/> class.
        /// </summary>
        public OpenIddictValidationOptions()
        {
            Events = null;
            EventsType = typeof(OpenIddictValidationProvider);
        }

        /// <summary>
        /// Gets or sets a boolean indicating whether a database call is made
        /// to validate the authorization associated with the received tokens.
        /// </summary>
        public bool EnableAuthorizationValidation { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether reference tokens are used.
        /// </summary>
        public bool UseReferenceTokens { get; set; }
    }
}
