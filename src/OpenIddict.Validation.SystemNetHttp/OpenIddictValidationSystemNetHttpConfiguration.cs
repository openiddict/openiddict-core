/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Net.Http.Headers;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation.SystemNetHttp
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation/System.Net.Http integration configuration is valid.
    /// </summary>
    public class OpenIddictValidationSystemNetHttpConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                  IConfigureNamedOptions<HttpClientFactoryOptions>
    {
#if !SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
        private readonly IServiceProvider _provider;

        public OpenIddictValidationSystemNetHttpConfiguration([NotNull] IServiceProvider provider)
            => _provider = provider;
#endif

        public void Configure([NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict System.Net.Http validation components.
            options.Handlers.AddRange(OpenIddictValidationSystemNetHttpHandlers.DefaultHandlers);
        }

        public void Configure([NotNull] HttpClientFactoryOptions options)
            => Debug.Fail("This infrastructure method shouldn't be called.");

        public void Configure([CanBeNull] string name, [NotNull] HttpClientFactoryOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var assembly = typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName();

            if (!string.Equals(name, assembly.Name, StringComparison.Ordinal))
            {
                return;
            }

            options.HttpClientActions.Add(client =>
            {
                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(
                    productName: assembly.Name,
                    productVersion: assembly.Version.ToString()));
            });

            options.HttpMessageHandlerBuilderActions.Add(builder =>
            {
#if SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
                var options = builder.Services.GetRequiredService<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>();
#else
                var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>();
#endif
                var policy = options.CurrentValue.HttpErrorPolicy;
                if (policy != null)
                {
                    builder.AdditionalHandlers.Add(new PolicyHttpMessageHandler(policy));
                }
            });
        }
    }
}
