/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace OpenIddict.Client.SystemNetHttp;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client/System.Net.Http integration configuration is valid.
/// </summary>
public class OpenIddictClientSystemNetHttpConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                          IConfigureNamedOptions<HttpClientFactoryOptions>
{
#if !SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
    private readonly IServiceProvider _serviceProvider;

    public OpenIddictClientSystemNetHttpConfiguration(IServiceProvider serviceProvider)
        => _serviceProvider = serviceProvider;
#endif

    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict System.Net.Http client components.
        options.Handlers.AddRange(OpenIddictClientSystemNetHttpHandlers.DefaultHandlers);
    }

    public void Configure(HttpClientFactoryOptions options)
        => Debug.Fail("This infrastructure method shouldn't be called.");

    public void Configure(string name, HttpClientFactoryOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        var assembly = typeof(OpenIddictClientSystemNetHttpOptions).Assembly.GetName();

        if (!string.Equals(name, assembly.Name, StringComparison.Ordinal))
        {
            return;
        }

        options.HttpClientActions.Add(client =>
        {
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(
                productName: assembly.Name!,
                productVersion: assembly.Version!.ToString()));
        });

        options.HttpMessageHandlerBuilderActions.Add(builder =>
        {
#if SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
            var options = builder.Services.GetRequiredService<IOptionsMonitor<OpenIddictClientSystemNetHttpOptions>>();
#else
            var options = _serviceProvider.GetRequiredService<IOptionsMonitor<OpenIddictClientSystemNetHttpOptions>>();
#endif
            var policy = options.CurrentValue.HttpErrorPolicy;
            if (policy is not null)
            {
                builder.AdditionalHandlers.Add(new PolicyHttpMessageHandler(policy));
            }
        });
    }
}
