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
using static OpenIddict.Validation.SystemNetHttp.OpenIddictValidationSystemNetHttpConstants;

namespace OpenIddict.Validation.SystemNetHttp
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict validation/System.Net.Http integration configuration is valid.
    /// </summary>
    public class OpenIddictValidationSystemNetHttpConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                  IConfigureNamedOptions<HttpClientFactoryOptions>
    {
        public void Configure([NotNull] OpenIddictValidationOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            // Register the built-in event handlers used by the OpenIddict System.Net.Http validation components.
            foreach (var handler in OpenIddictValidationSystemNetHttpHandlers.DefaultHandlers)
            {
                options.DefaultHandlers.Add(handler);
            }
        }

        public void Configure([NotNull] HttpClientFactoryOptions options)
            => Debug.Fail("This infrastructure method shouldn't be called.");

        public void Configure([CanBeNull] string name, [NotNull] HttpClientFactoryOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (!string.Equals(name, Clients.Discovery, StringComparison.Ordinal))
            {
                return;
            }

            options.HttpClientActions.Add(client =>
            {
                var name = typeof(OpenIddictValidationSystemNetHttpConfiguration).Assembly.GetName();

                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(
                    productName: name.Name,
                    productVersion: name.Version.ToString()));
            });

            options.HttpMessageHandlerBuilderActions.Add(builder =>
            {
                var options = builder.Services.GetRequiredService<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>();

                var policy = options.CurrentValue.HttpErrorPolicy;
                if (policy != null)
                {
                    builder.AdditionalHandlers.Add(new PolicyHttpMessageHandler(policy));
                }
            });
        }
    }
}
