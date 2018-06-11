/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Text.Encodings.Web;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictValidationHandler : OAuthValidationHandler
    {
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
