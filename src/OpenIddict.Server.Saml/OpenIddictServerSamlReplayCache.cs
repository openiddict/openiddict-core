/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Detects replayed SAML messages using the <see cref="IDistributedCache"/> registered in the
/// DI container or, if no distributed cache was registered, a private in-memory cache.
/// </summary>
/// <remarks>
/// <see cref="IDistributedCache"/> doesn't offer an atomic "add if not exists" operation: concurrent calls are
/// serialized in the current process but not across instances. Load-balanced deployments requiring strict
/// replay detection should register an <see cref="IOpenIddictServerSamlReplayCache"/> backed by an atomic store.
/// The private in-memory cache used when no distributed cache is registered is limited to 100,000 entries to prevent
/// resource exhaustion: when the limit is reached, entries can be evicted before they expire.
/// </remarks>
public sealed class OpenIddictServerSamlReplayCache : IOpenIddictServerSamlReplayCache
{
    /// <summary>
    /// The maximum number of entries stored in the private in-memory cache (each entry has a size of 1).
    /// </summary>
    private const long MemoryCacheSizeLimit = 100_000;

    private static readonly byte[] Marker = [1];

    private readonly IDistributedCache _cache;
    private readonly SemaphoreSlim _lock = new(initialCount: 1, maxCount: 1);
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlReplayCache"/> class.
    /// </summary>
    /// <param name="provider">The service provider, used to resolve the optional distributed cache.</param>
    /// <param name="options">The SAML options.</param>
    public OpenIddictServerSamlReplayCache(IServiceProvider provider, IOptionsMonitor<OpenIddictServerSamlOptions> options)
    {
        ArgumentNullException.ThrowIfNull(provider);

        // Note: MemoryDistributedCache uses the length of the stored values as the size of the cache entries.
        _cache = provider.GetService<IDistributedCache>() ??
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions { SizeLimit = MemoryCacheSizeLimit }));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public async ValueTask<bool> TryAddAsync(string identifier, DateTimeOffset expirationDate, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var key = "openiddict-saml-replay:" + OpenIddictServerSamlHelpers.HashIdentifier(identifier);

        await _lock.WaitAsync(cancellationToken);

        try
        {
            if (await _cache.GetAsync(key, cancellationToken) is not null)
            {
                return false;
            }

            await _cache.SetAsync(key, Marker, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = OpenIddictServerSamlHelpers.GetCacheLifetime(
                    expirationDate, _options.CurrentValue.TimeProvider.GetUtcNow())
            }, cancellationToken);

            return true;
        }

        finally
        {
            _lock.Release();
        }
    }
}
