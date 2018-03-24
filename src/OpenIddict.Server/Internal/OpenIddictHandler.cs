using System.ComponentModel;
using System.Text.Encodings.Web;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictHandler : OpenIdConnectServerHandler
    {
        public OpenIddictHandler(
            [NotNull] IOptionsMonitor<OpenIddictOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }
    }
}
