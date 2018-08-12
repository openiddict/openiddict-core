/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text.Encodings.Web;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation.Internal
{
    /// <summary>
    /// Provides the logic necessary to extract and validate tokens from HTTP requests.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    public class OpenIddictValidationHandler : OAuthValidationHandler
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationHandler"/> class.
        /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
        /// directly from your code. This API may change or be removed in future minor releases.
        /// </summary>
        public OpenIddictValidationHandler(
            [NotNull] IOptionsMonitor<OpenIddictValidationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }
    }
}
