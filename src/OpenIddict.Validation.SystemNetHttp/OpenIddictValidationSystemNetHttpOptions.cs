/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using Polly;
using Polly.Extensions.Http;

#if NET
using Microsoft.Extensions.Http.Resilience;
#endif

namespace OpenIddict.Validation.SystemNetHttp;

/// <summary>
/// Provides various settings needed to configure the OpenIddict validation/System.Net.Http integration.
/// </summary>
public sealed class OpenIddictValidationSystemNetHttpOptions
{
    /// <summary>
    /// Gets or sets the HTTP Polly error policy used by the internal OpenIddict HTTP clients.
    /// </summary>
    /// <remarks>
    /// Note: on .NET 8.0 and higher, this property is set to <see langword="null"/> by default.
    /// </remarks>
    public IAsyncPolicy<HttpResponseMessage>? HttpErrorPolicy { get; set; }
#if !NET
        = HttpPolicyExtensions.HandleTransientHttpError()
            .OrResult(static response => response.StatusCode is HttpStatusCode.NotFound)
            .WaitAndRetryAsync(4, static attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)));
#endif

#if NET
    /// <summary>
    /// Gets or sets the HTTP resilience pipeline used by the internal OpenIddict HTTP clients.
    /// </summary>
    /// <remarks>
    /// Note: this property is not used when <see cref="HttpErrorPolicy"/>
    /// is explicitly set to a non-<see langword="null"/> value.
    /// </remarks>
    public ResiliencePipeline<HttpResponseMessage>? HttpResiliencePipeline { get; set; }
        = new ResiliencePipelineBuilder<HttpResponseMessage>()
            .AddRetry(new HttpRetryStrategyOptions
            {
                DelayGenerator = static arguments => new(
                    TimeSpan.FromSeconds(Math.Pow(2, arguments.AttemptNumber))),
                MaxRetryAttempts = 4,
                ShouldHandle = static arguments => new(
                    HttpClientResiliencePredicates.IsTransient(arguments.Outcome) ||
                    arguments.Outcome.Result?.StatusCode is HttpStatusCode.NotFound)
            })
            .Build();
#endif

    /// <summary>
    /// Gets or sets the contact mail address used in the "From" header that is
    /// attached to the backchannel HTTP requests sent to the authorization server.
    /// </summary>
    public MailAddress? ContactAddress { get; set; }

    /// <summary>
    /// Gets or sets the product information used in the "User-Agent" header that is
    /// attached to the backchannel HTTP requests sent to the authorization server.
    /// </summary>
    public ProductInfoHeaderValue? ProductInformation { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the raw payloads of the HTTP responses returned by
    /// the remote server should be included in the logs when an invalid or unexpected response is received.
    /// </summary>
    /// <remarks>
    /// Note: raw payloads may contain sensitive data (e.g access tokens or refresh tokens).
    /// As such, this option should only be enabled in development environments.
    /// </remarks>
    public bool EnableSensitivePayloadLogging { get; set; }

    /// <summary>
    /// Gets or sets the decompression methods the OpenIddict validation/System.Net.Http integration
    /// is allowed to use to decode the compressed HTTP responses returned by the remote server.
    /// </summary>
    /// <remarks>
    /// Note: while HTTP compression is never opted-in by default, encoded responses returned by servers
    /// that enforce content compression are still decoded. This property can be used to exclude specific
    /// algorithms (e.g to mitigate a vulnerability affecting one of the decoders used by the runtime).
    /// <c>DecompressionMethods.All</c> can be used to allow all the algorithms supported by OpenIddict.
    /// </remarks>
    public DecompressionMethods AllowedDecompressionMethods { get; set; }
#if NET
        = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli;
#else
        // Note: on .NET Framework, only GZip is allowed by default, as Deflate and Brotli are not supported:
        // the HTTP "deflate" content coding requires a zlib-framed stream that can only be decoded using
        // ZLibStream (which is only available on .NET 6.0 and higher), and BrotliStream is not available.
        // Explicitly allowing Deflate or Brotli has no effect, as such responses are always rejected.
        = DecompressionMethods.GZip;
#endif

    /// <summary>
    /// Gets the user-defined actions used to amend the <see cref="HttpClient"/>
    /// instances created by the OpenIddict validation/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClient>> HttpClientActions { get; } = [];

    /// <summary>
    /// Gets the user-defined actions used to amend the <see cref="HttpClientHandler"/>
    /// instances created by the OpenIddict validation/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClientHandler>> HttpClientHandlerActions { get; } = [];
}
