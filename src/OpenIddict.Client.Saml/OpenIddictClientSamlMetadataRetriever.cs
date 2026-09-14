/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Net.Http;

namespace OpenIddict.Client.Saml;

/// <summary>
/// Retrieves SAML metadata documents from HTTPS or file URIs.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientSamlMetadataRetriever : IOpenIddictClientSamlMetadataRetriever, IDisposable
{
    private readonly HttpClient _client = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <inheritdoc/>
    public ValueTask<byte[]> RetrieveAsync(Uri address, int maximumSize, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        return ExecuteAsync(address, maximumSize, cancellationToken);

        async ValueTask<byte[]> ExecuteAsync(Uri address, int maximumSize, CancellationToken cancellationToken)
        {
            if (!address.IsAbsoluteUri)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0907));
            }

            if (address.IsFile)
            {
                var file = new FileInfo(address.LocalPath);
                if (file.Exists && file.Length > maximumSize)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0903));
                }

                using var stream = file.OpenRead();
                return await ReadAsync(stream, maximumSize, cancellationToken);
            }

            if (!string.Equals(address.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0907));
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, address);
            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0907));
            }

            if (response.Content.Headers.ContentLength > maximumSize)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0903));
            }

#if NET
            using var content = await response.Content.ReadAsStreamAsync(cancellationToken);
#else
            using var content = await response.Content.ReadAsStreamAsync();
#endif
            return await ReadAsync(content, maximumSize, cancellationToken);
        }

        static async Task<byte[]> ReadAsync(Stream stream, int maximumSize, CancellationToken cancellationToken)
        {
            using var output = new MemoryStream();

            var buffer = new byte[16 * 1024];
            int count;

            while ((count = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
            {
                if (output.Length + count > maximumSize)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0903));
                }

                output.Write(buffer, 0, count);
            }

            return output.ToArray();
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _client.Dispose();
}
