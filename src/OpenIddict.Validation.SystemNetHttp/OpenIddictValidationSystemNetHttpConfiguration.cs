/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;
using Polly;

#if NET
using Microsoft.Extensions.Http.Resilience;
#endif

namespace OpenIddict.Validation.SystemNetHttp;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict validation/System.Net.Http integration configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictValidationSystemNetHttpConfiguration : IConfigureOptions<OpenIddictValidationOptions>,
                                                                     IConfigureNamedOptions<HttpClientFactoryOptions>,
                                                                     IPostConfigureOptions<HttpClientFactoryOptions>
{
    private readonly IServiceProvider _provider;
    
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationSystemNetHttpConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictValidationSystemNetHttpConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void Configure(OpenIddictValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // Register the built-in event handlers used by the OpenIddict System.Net.Http validation components.
        options.Handlers.AddRange(OpenIddictValidationSystemNetHttpHandlers.DefaultHandlers);

        // Enable client_secret_basic, self_signed_tls_client_auth and tls_client_auth support by default.
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretBasic);
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.SelfSignedTlsClientAuth);
        options.ClientAuthenticationMethods.Add(ClientAuthenticationMethods.TlsClientAuth);
    }

    /// <inheritdoc/>
    public void Configure(HttpClientFactoryOptions options) => Configure(Options.DefaultName, options);

    /// <inheritdoc/>
    public void Configure(string? name, HttpClientFactoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var assembly = typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName();

        // Only amend the HTTP client factory options if the instance is managed by OpenIddict.
        if (string.IsNullOrEmpty(name) || !name.StartsWith(assembly.Name!, StringComparison.Ordinal))
        {
            return;
        }

        // Note: HttpClientFactory doesn't support flowing a list of properties that can be
        // accessed from the HttpClientAction or HttpMessageHandlerBuilderAction delegates
        // to dynamically amend the resulting HttpClient or HttpClientHandler instance.
        //
        // To work around this limitation, the OpenIddict System.Net.Http integration uses
        // an async-local context to flow per-instance properties and uses dynamic client
        // names to ensure the inner HttpClientHandler is not reused if the context differs.
        var context = OpenIddictValidationSystemNetHttpContext.Current ??
            throw new InvalidOperationException(SR.FormatID0516(nameof(OpenIddictValidationSystemNetHttpContext)));

        var settings = _provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>().CurrentValue;

        options.HttpClientActions.Add(static client =>
        {
            // By default, HttpClient uses a default timeout of 100 seconds and allows payloads of up to 2GB.
            // To help reduce the effects of malicious responses (e.g responses returned at a very slow pace
            // or containing an infine amount of data), the default values are amended to use lower values.
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
            var options = builder.Services.GetRequiredService<IOptionsMonitor<OpenIddictValidationSystemNetHttpOptions>>();

            // If applicable, add the handler responsible for replaying failed HTTP requests.
            //
            // Note: on .NET 8.0 and higher, the HTTP error policy is always set
            // to null by default and an HTTP resilience pipeline is used instead.
            if (options.CurrentValue.HttpErrorPolicy is IAsyncPolicy<HttpResponseMessage> policy)
            {
                builder.AdditionalHandlers.Add(new PolicyHttpMessageHandler(policy));
            }

#if NET
            else if (options.CurrentValue.HttpResiliencePipeline is ResiliencePipeline<HttpResponseMessage> pipeline)
            {
                builder.AdditionalHandlers.Add(new ResilienceHandler(pipeline));
            }
#endif
            if (builder.PrimaryHandler is not HttpClientHandler handler)
            {
                throw new InvalidOperationException(SR.FormatID0373(typeof(HttpClientHandler).FullName));
            }

            handler.ClientCertificateOptions = ClientCertificateOption.Manual;

            if (context.LocalCertificate is X509Certificate2 certificate)
            {
                // If a certificate was specified, immediately throw an excecption if it doesn't have
                // a private key attached to ensure it won't be silently discarded when initiating the
                // TLS handshake (which would result in a hard-to-debug scenario where the certificate
                // would be attached to the HTTP handler but would not be sent to the remote peer).
                if (!certificate.HasPrivateKey)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0514));
                }

                handler.ClientCertificates.Add(certificate);
            }
        });

        // Register the user-defined HTTP client handler actions.
        foreach (var action in settings.HttpClientHandlerActions)
        {
            options.HttpMessageHandlerBuilderActions.Add(builder => action(builder.PrimaryHandler as HttpClientHandler ??
                throw new InvalidOperationException(SR.FormatID0373(typeof(HttpClientHandler).FullName))));
        }
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, HttpClientFactoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var assembly = typeof(OpenIddictValidationSystemNetHttpOptions).Assembly.GetName();

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

            // Note: automatic content decompression can be enabled by constructing an HttpClient wrapping
            // a generic HttpClientHandler, a SocketsHttpHandler or a WinHttpHandler instance with the
            // AutomaticDecompression property set to the desired algorithms (e.g GZip, Deflate or Brotli).
            //
            // Unfortunately, while convenient and efficient, relying on this property has a downside:
            // setting AutomaticDecompression always overrides the Accept-Encoding header of all requests
            // to include the selected algorithms without offering a way to make this behavior opt-in.
            // Sadly, using HTTP content compression with transport security enabled has security implications
            // that could potentially lead to compression side-channel attacks if the client is used with
            // remote endpoints that reflect user-defined data and contain secret values (e.g BREACH attacks).
            //
            // Since OpenIddict itself cannot safely assume such scenarios will never happen (e.g a token request
            // will typically be sent with an authorization code that can be defined by a malicious user and can
            // potentially be reflected in the token response depending on the configuration of the remote server),
            // it is safer to disable compression by default by not sending an Accept-Encoding header while
            // still allowing encoded responses to be processed (e.g StackExchange forces content compression
            // for all the supported HTTP APIs even if no Accept-Encoding header is explicitly sent by the client).
            //
            // For these reasons, OpenIddict doesn't rely on the automatic decompression feature and uses
            // a custom event handler to deal with GZip/Deflate/Brotli-encoded responses, so that servers
            // that require using HTTP compression can be supported without having to use it for all servers.
            if (handler.SupportsAutomaticDecompression)
            {
                handler.AutomaticDecompression = DecompressionMethods.None;
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
        });
    }
}
