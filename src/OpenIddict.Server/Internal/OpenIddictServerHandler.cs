using System;
using System.ComponentModel;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server
{
    [EditorBrowsable(EditorBrowsableState.Never)]
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

        protected override async Task InitializeEventsAsync()
        {
            await base.InitializeEventsAsync();

            // If an application provider instance or type was specified, import the application provider events.
            if (Options.ApplicationProvider != null || Options.ApplicationProviderType != null)
            {
                // Resolve the user provider from the options or from the services container.
                var provider = Options.ApplicationProvider;
                if (provider == null)
                {
                    provider = Context.RequestServices.GetService(Options.ApplicationProviderType) as OpenIdConnectServerProvider;
                }

                if (provider == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The application provider cannot be resolved from the dependency injection container. ")
                        .Append("Make sure it is correctly registered in 'ConfigureServices(IServiceCollection services)'.")
                        .ToString());
                }

                // Update the main provider to invoke the user provider's event handlers.
                Provider.Import(provider);
            }
        }

        private new OpenIddictServerOptions Options => (OpenIddictServerOptions) base.Options;

        private OpenIddictServerProvider Provider => (OpenIddictServerProvider) base.Events;
    }
}
