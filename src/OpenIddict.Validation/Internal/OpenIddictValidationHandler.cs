/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
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

        protected override async Task InitializeEventsAsync()
        {
            await base.InitializeEventsAsync();

            // If an application provider instance or type was specified, import the application provider events.
            if (Options.ApplicationEvents != null || Options.ApplicationEventsType != null)
            {
                // Resolve the user provider from the options or from the services container.
                var events = Options.ApplicationEvents;
                if (events == null)
                {
                    events = Context.RequestServices.GetService(Options.ApplicationEventsType) as OAuthValidationEvents;
                }

                if (events == null)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The application events cannot be resolved from the dependency injection container. ")
                        .Append("Make sure they are correctly registered in 'ConfigureServices(IServiceCollection services)'.")
                        .ToString());
                }

                // Update the main events to invoke the user provider's event handlers.
                Events.Import(events);
            }
        }

        private new OpenIddictValidationEvents Events => (OpenIddictValidationEvents) base.Events;

        private new OpenIddictValidationOptions Options => (OpenIddictValidationOptions) base.Options;
    }
}
