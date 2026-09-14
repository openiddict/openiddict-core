/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Retrieves the request objects passed by reference using an external HTTPS "request_uri" parameter
/// (RFC 9101, section 5.2 and OpenID Connect Core, section 6.2) using System.Net.Http.
/// </summary>
/// <remarks>
/// SSRF mitigations: only HTTPS URIs without user information are fetched, redirections are not followed,
/// proxies and cookies are not used, all the addresses resolved for the host must be allowed by
/// <see cref="OpenIddictServerSystemNetHttpOptions.RemoteAddressFilter"/> and the response time,
/// size and media type are restricted.
/// </remarks>
public sealed class OpenIddictServerSystemNetHttpRequestObjectFetcher : IOpenIddictServerRequestObjectFetcher, IDisposable
{
    /// <summary>
    /// Represents the maximum number of request objects kept in the cache.
    /// </summary>
    private const int MaximumCacheEntries = 1_024;

    private static readonly UTF8Encoding Encoding = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.Ordinal);
    private readonly HttpClient _client;
    private readonly ILogger _logger;
    private readonly IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSystemNetHttpRequestObjectFetcher"/> class.
    /// </summary>
    /// <param name="options">The OpenIddict server/System.Net.Http integration options.</param>
    /// <param name="logger">The logger.</param>
    public OpenIddictServerSystemNetHttpRequestObjectFetcher(
        IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> options,
        ILogger<OpenIddictServerSystemNetHttpRequestObjectFetcher> logger)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _client = CreateClient(CreateHandler());
    }

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSystemNetHttpRequestObjectFetcher"/> class
    /// using the specified HTTP message handler. The built-in remote address filtering and redirection
    /// restrictions are not applied: the handler is responsible for enforcing them.
    /// </summary>
    /// <param name="options">The OpenIddict server/System.Net.Http integration options.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="handler">The HTTP message handler.</param>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSystemNetHttpRequestObjectFetcher(
        IOptionsMonitor<OpenIddictServerSystemNetHttpOptions> options,
        ILogger<OpenIddictServerSystemNetHttpRequestObjectFetcher> logger,
        HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _client = CreateClient(handler);
    }

    /// <inheritdoc/>
    public async ValueTask<string?> FetchAsync(Uri uri, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(uri);

        // Note: the OpenIddict server already validates the request URI but this check
        // is repeated here to ensure the fetcher can't be used to retrieve other resources.
        if (!uri.IsAbsoluteUri || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.IsNullOrEmpty(uri.UserInfo))
        {
            return null;
        }

        var options = _options.CurrentValue;
        var provider = options.TimeProvider ?? TimeProvider.System;

        // Note: the fragment is part of the cache key as it may contain the hash of the request object.
        if (_cache.TryGetValue(uri.AbsoluteUri, out Entry? entry))
        {
            if (entry.ExpirationDate > provider.GetUtcNow())
            {
                return entry.Value;
            }

            _cache.TryRemove(uri.AbsoluteUri, out _);
        }

        using var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        source.CancelAfter(options.RequestObjectTimeout);

        try
        {
            // Note: the fragment is never sent to the remote server.
            using var request = new HttpRequestMessage(HttpMethod.Get, uri.GetLeftPart(UriPartial.Query));

            foreach (var type in options.RequestObjectContentTypes)
            {
                request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(type));
            }

            using var response = await _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, source.Token);

            // Note: redirections are deliberately not followed (RFC 9101, section 10.4.1).
            if (response.StatusCode is not HttpStatusCode.OK)
            {
                _logger.LogInformation(6729, SR.GetResourceString(SR.ID6729), uri, (int) response.StatusCode);

                return null;
            }

            if (response.Content.Headers.ContentType?.MediaType is not string media ||
                !options.RequestObjectContentTypes.Contains(media))
            {
                _logger.LogInformation(6730, SR.GetResourceString(SR.ID6730), uri,
                    response.Content.Headers.ContentType?.MediaType);

                return null;
            }

            if (response.Content.Headers.ContentLength > options.MaximumRequestObjectSize)
            {
                _logger.LogInformation(6731, SR.GetResourceString(SR.ID6731), uri);

                return null;
            }

            var buffer = await ReadAsync(response.Content, options.MaximumRequestObjectSize, source.Token);
            if (buffer is null)
            {
                _logger.LogInformation(6731, SR.GetResourceString(SR.ID6731), uri);

                return null;
            }

            string value;

            try
            {
                value = Encoding.GetString(buffer.GetBuffer(), 0, (int) buffer.Length);
            }

            catch (DecoderFallbackException)
            {
                _logger.LogInformation(6734, SR.GetResourceString(SR.ID6734), uri);

                return null;
            }

            var now = provider.GetUtcNow();
            var lifetime = GetFreshnessLifetime(response, now);
            if (lifetime > options.MaximumRequestObjectCacheLifetime)
            {
                lifetime = options.MaximumRequestObjectCacheLifetime;
            }

            if (lifetime > TimeSpan.Zero)
            {
                AddToCache(uri.AbsoluteUri, new Entry(value, now + lifetime), now);
            }

            return value;
        }

        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogInformation(6732, SR.GetResourceString(SR.ID6732), uri);

            return null;
        }

        catch (HttpRequestException exception)
        {
            _logger.LogInformation(6733, exception, SR.GetResourceString(SR.ID6733), uri);

            return null;
        }
    }

    /// <inheritdoc/>
    public void Dispose() => _client.Dispose();

    private void AddToCache(string key, Entry entry, DateTimeOffset now)
    {
        if (_cache.Count >= MaximumCacheEntries)
        {
            foreach (var item in _cache)
            {
                if (item.Value.ExpirationDate <= now)
                {
                    _cache.TryRemove(item.Key, out _);
                }
            }

            // If the cache is still full, don't cache the request object.
            if (_cache.Count >= MaximumCacheEntries)
            {
                return;
            }
        }

        _cache[key] = entry;
    }

    /// <summary>
    /// Computes the freshness lifetime of the response, as defined by RFC 9111, section 4.2.1.
    /// Responses that don't explicitly define a freshness lifetime are not cached.
    /// </summary>
    private static TimeSpan GetFreshnessLifetime(HttpResponseMessage response, DateTimeOffset now)
    {
        if (response.Headers.CacheControl is CacheControlHeaderValue control)
        {
            if (control.NoStore || control.NoCache)
            {
                return TimeSpan.Zero;
            }

            if ((control.SharedMaxAge ?? control.MaxAge) is TimeSpan age)
            {
                return age - (response.Headers.Age ?? TimeSpan.Zero);
            }
        }

        if (response.Content.Headers.Expires is DateTimeOffset expires)
        {
            return expires - (response.Headers.Date ?? now);
        }

        return TimeSpan.Zero;
    }

    private static async Task<MemoryStream?> ReadAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
#if NET
        using var stream = await content.ReadAsStreamAsync(cancellationToken);
#else
        using var stream = await content.ReadAsStreamAsync();
#endif
        var result = new MemoryStream();
        var buffer = new byte[4096];

        while (true)
        {
#if NET
            var count = await stream.ReadAsync(buffer.AsMemory(), cancellationToken);
#else
            var count = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
#endif
            if (count is 0)
            {
                return result;
            }

            if (result.Length + count > limit)
            {
                return null;
            }

            result.Write(buffer, 0, count);
        }
    }

    private static HttpClient CreateClient(HttpMessageHandler handler) => new(handler, disposeHandler: true)
    {
        // Note: the timeout is enforced using a linked cancellation token source.
        Timeout = System.Threading.Timeout.InfiniteTimeSpan
    };

    private HttpMessageHandler CreateHandler()
    {
#if NET
        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            UseCookies = false,
            UseProxy = false,

            // Note: the remote addresses are validated when the connection is established (and not before sending the
            // request) to ensure the validated addresses are the ones actually used, which prevents DNS rebinding attacks.
            ConnectCallback = async (context, cancellationToken) =>
            {
                var addresses = await ResolveAddressesAsync(context.DnsEndPoint.Host, cancellationToken);

                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

                try
                {
                    await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, cancellationToken);

                    return new NetworkStream(socket, ownsSocket: true);
                }

                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };
#else
        return new AddressValidationHandler(this, new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            UseProxy = false
        });
#endif
    }

    private async Task<IPAddress[]> ResolveAddressesAsync(string host, CancellationToken cancellationToken)
    {
        var addresses = IPAddress.TryParse(host.Trim('[', ']'), out IPAddress? address) ? [address] :
#if NET
            await Dns.GetHostAddressesAsync(host, cancellationToken);
#else
            await Dns.GetHostAddressesAsync(host);
#endif
        if (addresses.Length is 0)
        {
            throw new HttpRequestException(SR.FormatID0930(host));
        }

        var filter = _options.CurrentValue.RemoteAddressFilter;

        foreach (var candidate in addresses)
        {
            if (!filter(candidate))
            {
                _logger.LogWarning(6728, SR.GetResourceString(SR.ID6728), host, candidate);

                throw new HttpRequestException(SR.FormatID0930(host));
            }
        }

        return addresses;
    }

#if !NET
    /// <summary>
    /// Validates the remote addresses before sending the request (on .NET Framework, the connection
    /// establishment can't be intercepted, so the addresses are resolved and validated beforehand).
    /// </summary>
    private sealed class AddressValidationHandler(OpenIddictServerSystemNetHttpRequestObjectFetcher fetcher,
        HttpMessageHandler handler) : DelegatingHandler(handler)
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await fetcher.ResolveAddressesAsync(request.RequestUri!.DnsSafeHost, cancellationToken);

            return await base.SendAsync(request, cancellationToken);
        }
    }
#endif

    private sealed class Entry(string value, DateTimeOffset expirationDate)
    {
        public string Value { get; } = value;

        public DateTimeOffset ExpirationDate { get; } = expirationDate;
    }
}
