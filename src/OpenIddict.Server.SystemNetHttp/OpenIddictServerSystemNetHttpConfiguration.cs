/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Polly;

#if SUPPORTS_HTTP_CLIENT_RESILIENCE
using Microsoft.Extensions.Http.Resilience;
#endif

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict server/System.Net.Http integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerSystemNetHttpConfiguration : IConfigureOptions<OpenIddictServerOptions>,
                                                                 IConfigureNamedOptions<HttpClientFactoryOptions>,
                                                                 IPostConfigureOptions<HttpClientFactoryOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSystemNetHttpConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictServerSystemNetHttpConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(OpenIddictServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict System.Net.Http server components.
        options.Handlers.AddRange(OpenIddictServerSystemNetHttpHandlers.DefaultHandlers);
    }

    /// <inheritdoc/>
    public void Configure(HttpClientFactoryOptions options) => Configure(Options.DefaultName, options);

    /// <inheritdoc/>
    public void Configure(string? name, HttpClientFactoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var assembly = typeof(OpenIddictServerSystemNetHttpOptions).Assembly.GetName();

        // Only amend the HTTP client factory options if the instance is managed by OpenIddict.
        if (string.IsNullOrEmpty(name) || !name.StartsWith(assembly.Name!, StringComparison.Ordinal))
        {
            return;
        }

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictServerSystemNetHttpOptions>>().CurrentValue;

        options.HttpClientActions.Add(static client =>
        {
            // By default, HttpClient uses a default timeout of 100 seconds and allows payloads of up to 2GB.
            // To help reduce the effects of malicious responses (e.g responses returned at a very slow pace
            // or containing an infinite amount of data), the default values are amended to use lower values.
            client.MaxResponseContentBufferSize = 10 * 1024 * 1024;
            client.Timeout = TimeSpan.FromMinutes(1);
        });

        // Register the user-defined HTTP client actions.
        foreach (var action in settings.HttpClientActions)
        {
            options.HttpClientActions.Add(action);
        }

        options.HttpMessageHandlerBuilderActions.Add(builder =>
        {
            var options = builder.Services.GetRequiredService<IOptionsMonitor<OpenIddictServerSystemNetHttpOptions>>();

            // If applicable, add the handler responsible for replaying failed HTTP requests.
            //
            // Note: on .NET 8.0 and higher, the HTTP error policy is always set
            // to null by default and an HTTP resilience pipeline is used instead.
            if (options.CurrentValue.HttpErrorPolicy is IAsyncPolicy<HttpResponseMessage> policy)
            {
                builder.AdditionalHandlers.Add(new PolicyHttpMessageHandler(policy));
            }

#if SUPPORTS_HTTP_CLIENT_RESILIENCE
            else if (options.CurrentValue.HttpResiliencePipeline is ResiliencePipeline<HttpResponseMessage> pipeline)
            {
#pragma warning disable EXTEXP0001
                builder.AdditionalHandlers.Add(new ResilienceHandler(pipeline));
#pragma warning restore EXTEXP0001
            }
#endif
            if (builder.PrimaryHandler is not HttpClientHandler handler)
            {
                throw new InvalidOperationException(SR.FormatID0373(typeof(HttpClientHandler).FullName));
            }
        });

        // Register the user-defined HTTP client handler actions.
        foreach (var action in settings.HttpClientHandlerActions)
        {
            options.HttpMessageHandlerBuilderActions.Add(builder => action(
                builder.PrimaryHandler as HttpClientHandler ??
                    throw new InvalidOperationException(SR.FormatID0373(typeof(HttpClientHandler).FullName))));
        }
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, HttpClientFactoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var assembly = typeof(OpenIddictServerSystemNetHttpOptions).Assembly.GetName();

        // Only amend the HTTP client factory options if the instance is managed by OpenIddict.
        if (string.IsNullOrEmpty(name) || !name.StartsWith(assembly.Name!, StringComparison.Ordinal))
        {
            return;
        }

        options.HttpMessageHandlerBuilderActions.Insert(0, static builder =>
        {
            // Note: Microsoft.Extensions.Http 9.0+ no longer uses HttpClientHandler as the default instance
            // for PrimaryHandler on platforms that support SocketsHttpHandler. Since OpenIddict requires an
            // HttpClientHandler instance, it is manually reassigned here if it's not an HttpClientHandler.
            if (builder.PrimaryHandler is not HttpClientHandler)
            {
                builder.PrimaryHandler = new HttpClientHandler();
            }
        });

        options.HttpMessageHandlerBuilderActions.Add(static builder =>
        {
            if (builder.PrimaryHandler is not HttpClientHandler handler)
            {
                throw new InvalidOperationException(SR.FormatID0373(typeof(HttpClientHandler).FullName));
            }

            // Disable automatic content decompression for security reasons (BREACH attacks).
            if (handler.SupportsAutomaticDecompression)
            {
                handler.AutomaticDecompression = DecompressionMethods.None;
            }

            // Disable cookies support for security reasons.
            handler.UseCookies = false;
        });
    }
}
