/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text.Encodings.Web;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.Internal
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    public class OpenIddictServerHandler : OpenIdConnectServerHandler
    {
        public OpenIddictServerHandler(
            [NotNull] IOptionsMonitor<OpenIddictServerOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }
    }
}
