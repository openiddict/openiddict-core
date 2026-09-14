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
/// <para>
/// <see cref="IDistributedCache"/> doesn't offer an atomic "add if not exists" operation: concurrent calls using the same
/// identifier are serialized in the current process but not across instances. Load-balanced deployments requiring strict
/// replay detection should register an <see cref="IOpenIddictServerSamlReplayCache"/> backed by an atomic store.
/// </para>
/// <para>
/// This cache fails closed: if an entry couldn't be stored (e.g because a size-limited cache is full), the message is
/// treated as a replay and rejected. The private in-memory cache used when no distributed cache is registered is limited
/// to 100,000 entries that are never evicted before they expire: once full, new messages are rejected until entries expire.
/// Production deployments should register a shared distributed cache (or a custom replay cache) sized for their traffic.
/// </para>
/// </remarks>
public sealed class OpenIddictServerSamlReplayCache : IOpenIddictServerSamlReplayCache
{
    /// <summary>
    /// The default maximum number of entries stored in the private in-memory cache (each entry has a size of 1).
    /// </summary>
    private const long MemoryCacheSizeLimit = 100_000;

    private static readonly byte[] Marker = [1];

    private readonly IDistributedCache? _distributedCache;
    private readonly MemoryCache? _memoryCache;
    private readonly OpenIddictServerSamlKeyedLock _locks = new();
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlReplayCache"/> class.
    /// </summary>
    /// <param name="provider">The service provider, used to resolve the optional distributed cache.</param>
    /// <param name="options">The SAML options.</param>
    public OpenIddictServerSamlReplayCache(IServiceProvider provider, IOptionsMonitor<OpenIddictServerSamlOptions> options)
        : this(provider, options, MemoryCacheSizeLimit)
    {
    }

    internal OpenIddictServerSamlReplayCache(IServiceProvider provider,
        IOptionsMonitor<OpenIddictServerSamlOptions> options, long sizeLimit)
    {
        ArgumentNullException.ThrowIfNull(provider);

        _options = options ?? throw new ArgumentNullException(nameof(options));
        _distributedCache = provider.GetService<IDistributedCache>();

        if (_distributedCache is null)
        {
            _memoryCache = new MemoryCache(Options.Create(new MemoryCacheOptions { SizeLimit = sizeLimit }));
        }
    }

    /// <inheritdoc/>
    public ValueTask<bool> TryAddAsync(string identifier, DateTimeOffset expirationDate, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var key = "openiddict-saml-replay:" + OpenIddictServerSamlHelpers.HashIdentifier(identifier);
        var lifetime = OpenIddictServerSamlHelpers.GetCacheLifetime(expirationDate, _options.CurrentValue.TimeProvider.GetUtcNow());

        return _memoryCache is not null ? new(TryAdd(_memoryCache, key, lifetime)) : TryAddDistributedAsync(key, lifetime, cancellationToken);
    }

    private bool TryAdd(MemoryCache cache, string key, TimeSpan lifetime)
    {
        lock (_locks.GetSynchronizationObject(key))
        {
            if (cache.TryGetValue(key, out _))
            {
                return false;
            }

            // Note: entries are never evicted before they expire (a compaction would re-enable replays).
            // When the size limit is reached, MemoryCache silently discards new entries: in this case,
            // the message is rejected, as its identifier cannot be remembered (fail closed).
            cache.Set(key, Marker, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = lifetime,
                Priority = CacheItemPriority.NeverRemove,
                Size = 1
            });

            return cache.TryGetValue(key, out _);
        }
    }

    private async ValueTask<bool> TryAddDistributedAsync(string key, TimeSpan lifetime, CancellationToken cancellationToken)
    {
        var cache = _distributedCache!;
        var semaphore = _locks.GetSemaphore(key);

        await semaphore.WaitAsync(cancellationToken);

        try
        {
            if (await cache.GetAsync(key, cancellationToken) is not null)
            {
                return false;
            }

            await cache.SetAsync(key, Marker, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = lifetime
            }, cancellationToken);

            // Note: some caches (e.g a size-limited MemoryDistributedCache) silently discard new entries:
            // to fail closed, the message is rejected if the entry cannot be read back.
            return await cache.GetAsync(key, cancellationToken) is not null;
        }

        finally
        {
            semaphore.Release();
        }
    }
}
