/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using Polly;
using Polly.Extensions.Http;

#if SUPPORTS_HTTP_CLIENT_RESILIENCE
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
#if !SUPPORTS_HTTP_CLIENT_RESILIENCE
        = HttpPolicyExtensions.HandleTransientHttpError()
            .OrResult(static response => response.StatusCode is HttpStatusCode.NotFound)
            .WaitAndRetryAsync(4, static attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt)));
#endif

#if SUPPORTS_HTTP_CLIENT_RESILIENCE
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
    /// Gets the user-defined actions used to amend the <see cref="HttpClient"/>
    /// instances created by the OpenIddict validation/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClient>> HttpClientActions { get; } = [];

    /// <summary>
    /// Gets the user-defined actions used to amend the <see cref="HttpClientHandler"/>
    /// instances created by the OpenIddict validation/System.Net.Http integration.
    /// </summary>
    public List<Action<HttpClientHandler>> HttpClientHandlerActions { get; } = [];

    /// <summary>
    /// Gets or sets the delegate called by OpenIddict when trying to resolve the
    /// self-signed TLS client authentication certificate that will be used for OAuth 2.0
    /// mTLS-based client authentication (self_signed_tls_client_auth), if applicable.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, OpenIddict automatically tries to resolve the
    /// X.509 certificate from the signing credentials attached to the validation options
    /// (in this case, the X.509 certificate MUST include the digital signature and
    /// client authentication key usages to be automatically selected by OpenIddict).
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public Func<X509Certificate2?> SelfSignedTlsClientAuthenticationCertificateSelector { get; set; } = default!;

    /// <summary>
    /// Gets or sets the delegate called by OpenIddict when trying to resolve the TLS
    /// client authentication certificate that will be used for OAuth 2.0 mTLS-based
    /// client authentication (tls_client_auth), if applicable.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, OpenIddict automatically tries to resolve the
    /// X.509 certificate from the signing credentials attached to the validation options
    /// (in this case, the X.509 certificate MUST include the digital signature and
    /// client authentication key usages to be automatically selected by OpenIddict).
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public Func<X509Certificate2?> TlsClientAuthenticationCertificateSelector { get; set; } = default!;
}
