/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Polly;

namespace OpenIddict.Client.SystemNetHttp;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict client/System.Net.Http integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSystemNetHttpConfiguration : IConfigureOptions<OpenIddictClientOptions>,
                                                                 IConfigureNamedOptions<HttpClientFactoryOptions>
{
#if !SUPPORTS_SERVICE_PROVIDER_IN_HTTP_MESSAGE_HANDLER_BUILDER
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSystemNetHttpConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictClientSystemNetHttpConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));
#endif

    /// <inheritdoc/>
    public void Configure(OpenIddictClientOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Register the built-in event handlers used by the OpenIddict System.Net.Http client components.
        options.Handlers.AddRange(OpenIddictClientSystemNetHttpHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void Configure(HttpClientFactoryOptions options) => Configure(Options.DefaultName, options);

    /// <inheritdoc/>
    public void Configure(string? name, HttpClientFactoryOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

        // Only amend the HTTP client factory options if the instance is managed by OpenIddict.
        var assembly = typeof(OpenIddictClientSystemNetHttpOptions).Assembly.GetName();
        if (string.IsNullOrEmpty(name) || !name.StartsWith(assembly.Name!, StringComparison.Ordinal))
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
            var options = builder.Services.GetRequiredService<IOptionsMonitor<OpenIddictClientSystemNetHttpOptions>>();
#else
            var options = _provider.GetRequiredService<IOptionsMonitor<OpenIddictClientSystemNetHttpOptions>>();
#endif
            if (builder.PrimaryHandler is not HttpClientHandler handler)
            {
                throw new InvalidOperationException(SR.FormatID0373(typeof(HttpClientHandler).FullName));
            }

            // OpenIddict uses IHttpClientFactory to manage the creation of the HTTP clients and
            // their underlying HTTP message handlers, that are cached for the specified duration
            // and re-used to process multiple requests during that period. While remote APIs are
            // typically not expected to return cookies, it is in practice a very frequent case,
            // which poses a serious security issue when the cookies are shared across multiple
            // requests (which is the case when the same message handler is cached and re-used).
            //
            // To avoid that, cookies support is explicitly disabled here, for security reasons.
            handler.UseCookies = false;

            // Unless the HTTP error policy was explicitly disabled in the options,
            // add the HTTP handler responsible for replaying failed HTTP requests.
            if (options.CurrentValue.HttpErrorPolicy is IAsyncPolicy<HttpResponseMessage> policy)
            {
                builder.AdditionalHandlers.Add(new PolicyHttpMessageHandler(policy));
            }
        });
    }
}
