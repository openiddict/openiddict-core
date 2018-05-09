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
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictValidationMiddleware : OAuthValidationMiddleware
    {
        public OpenIddictValidationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<OpenIddictValidationOptions> options,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, encoder, dataProtectionProvider)
        {
        }

        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler()
            => new OpenIddictValidationHandler();
    }
}
