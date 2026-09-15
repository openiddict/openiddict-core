/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Sends SAML messages using the SOAP 1.1 binding over HTTP (SAML bindings, 3.2.2). Redirections are not followed.
/// </summary>
public sealed class OpenIddictServerSamlSoapClient : IOpenIddictServerSamlSoapClient, IDisposable
{
    private readonly HttpClient _client = new(new HttpClientHandler { AllowAutoRedirect = false })
    {
        Timeout = Timeout.InfiniteTimeSpan
    };

    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlSoapClient"/> class.
    /// </summary>
    /// <param name="options">The SAML options.</param>
    public OpenIddictServerSamlSoapClient(IOptionsMonitor<OpenIddictServerSamlOptions> options)
        => _options = options ?? throw new ArgumentNullException(nameof(options));

    /// <inheritdoc/>
    public async ValueTask<string?> SendAsync(Uri url, string envelope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentException.ThrowIfNullOrEmpty(envelope);

        using var request = new HttpRequestMessage(HttpMethod.Post, url)
        {
            Content = new StringContent(envelope, Encoding.UTF8, OpenIddictServerSamlConstants.MediaTypes.Soap)
        };

        // Note: the SOAPAction header is required by SOAP 1.1 (SAML bindings, 3.2.3.3).
        request.Headers.TryAddWithoutValidation("SOAPAction", "\"http://www.oasis-open.org/committees/security\"");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIddictServerSamlConstants.MediaTypes.Soap));

        try
        {
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            // Note: SOAP faults are returned using a 500 status code (SAML bindings, 3.2.3.3).
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

#if NET
            using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
#else
            using var stream = await response.Content.ReadAsStreamAsync();
#endif
            using var output = new MemoryStream();

            var maximum = _options.CurrentValue.MaximumMessageSize;
            var buffer = new byte[4096];
            int count;

            while ((count = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
            {
                if (output.Length + count > maximum)
                {
                    return null;
                }

                output.Write(buffer, 0, count);
            }

            return Encoding.UTF8.GetString(output.ToArray());
        }

        catch (Exception exception) when (exception is HttpRequestException or IOException ||
            (exception is OperationCanceledException && !cancellationToken.IsCancellationRequested))
        {
            return null;
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _client.Dispose();
}
