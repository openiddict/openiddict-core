/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using AspNet.Security.OAuth.Validation;

namespace OpenIddict.Validation
{
    public class OpenIddictValidationOptions : OAuthValidationOptions
    {
        /// <summary>
        /// Gets or sets a boolean indicating whether reference tokens are used.
        /// </summary>
        public bool UseReferenceTokens { get; set; }
    }
}
