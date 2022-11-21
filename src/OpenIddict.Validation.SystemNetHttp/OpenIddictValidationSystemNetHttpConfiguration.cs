/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation.SystemNetHttp;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict validation/System.Net.Http integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictValidationSystemNetHttpConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                     IConfigureNamedOptions<HttpClientFactoryOptions>
{
#if !SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
    private readonly IServiceProvider _provider;

    public OpenIddictValidationSystemNetHttpConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));
#endif

    public void Configure(OpenIddictValidationOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict System.Net.Http validation components.
        options.Handlers.AddRange(OpenIddictValidationSystemNetHttpHandlers.DefaultHandlers);
    }

    public void Configure(HttpClientFactoryOptions options) => Configure(Options.DefaultName, options);

    public void Configure(string? name, HttpClientFactoryOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Only amend the HTTP client factory options if the instance is managed by OpenIddict.
        var assembly = typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName();
        if (!string.Equals(name, assembly.Name, StringComparison.Ordinal))
        {
            return;
        }

        options.HttpClientActions.Add(options =>
        {
            // By default, HttpClient uses a default timeout of 100 seconds and allows payloads of up to 2GB.
            // To help reduce the effects of malicious responses (e.g responses returned at a very slow pace
            // or containing an infine amount of data), the default values are amended to use lower values.
            options.MaxResponseContentBufferSize = 10 * 1024 * 1024;
            options.Timeout = TimeSpan.FromMinutes(1);
        });

        options.HttpMessageHandlerBuilderActions.Add(builder =>
        {
#if SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
            var options = builder.Services.GetRequiredService<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>();
#else
            var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>();
#endif
            var policy = options.CurrentValue.HttpErrorPolicy;
            if (policy is not null)
            {
                builder.AdditionalHandlers.Add(new PolicyHttpMessageHandler(policy));
            }
        });
    }
}
