/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to cache resources after retrieving them from the store.
/// </summary>
/// <typeparam name="TResource">The type of the Resource entity.</typeparam>
public sealed class OpenIddictResourceCache<TResource> : IOpenIddictResourceCache<TResource>, IDisposable where TResource : class
{
    private readonly MemoryCache _cache;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _signals;
    private readonly IOpenIddictResourceStore<TResource> _store;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictResourceCache{TResource}"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <param name="store">The store.</param>
    public OpenIddictResourceCache(
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictResourceStore<TResource> store)
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = (options ?? throw new ArgumentNullException(nameof(options))).CurrentValue.EntityCacheLimit
        });

        _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <inheritdoc/>
    public async ValueTask AddAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        _cache.Remove(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(resource, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindByNameAsync),
            Name = await _store.GetNameAsync(resource, cancellationToken)
        });

        await CreateEntryAsync(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(resource, cancellationToken)
        }, resource, cancellationToken);

        await CreateEntryAsync(new
        {
            Method = nameof(FindByNameAsync),
            Name = await _store.GetNameAsync(resource, cancellationToken)
        }, resource, cancellationToken);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (var signal in _signals)
        {
            signal.Value.Dispose();
        }

        _cache.Dispose();
    }

    /// <inheritdoc/>
    public ValueTask<TResource?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var parameters = new
        {
            Method = nameof(FindByIdAsync),
            Identifier = identifier
        };

        if (_cache.TryGetValue(parameters, out TResource? resource))
        {
            return new(resource);
        }

        return new(ExecuteAsync());

        async Task<TResource?> ExecuteAsync()
        {
            if ((resource = await _store.FindByIdAsync(identifier, cancellationToken)) is not null)
            {
                await AddAsync(resource, cancellationToken);
            }

            await CreateEntryAsync(parameters, resource, cancellationToken);

            return resource;
        }
    }

    /// <inheritdoc/>
    public ValueTask<TResource?> FindByNameAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var parameters = new
        {
            Method = nameof(FindByNameAsync),
            Name = name
        };

        if (_cache.TryGetValue(parameters, out TResource? resource))
        {
            return new(resource);
        }

        async Task<TResource?> ExecuteAsync()
        {
            if ((resource = await _store.FindByNameAsync(name, cancellationToken)) is not null)
            {
                await AddAsync(resource, cancellationToken);
            }

            await CreateEntryAsync(parameters, resource, cancellationToken);

            return resource;
        }

        return new(ExecuteAsync());
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TResource> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
    {
        if (names.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0203), nameof(names));
        }

        // Note: this method is only partially cached.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResource> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var resource in _store.FindByNamesAsync(names, cancellationToken))
            {
                await AddAsync(resource, cancellationToken);

                yield return resource;
            }
        }
    }

    /// <inheritdoc/>
    public async ValueTask RemoveAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var identifier = await _store.GetIdAsync(resource, cancellationToken);
        if (string.IsNullOrEmpty(identifier))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0196));
        }

        if (_signals.TryRemove(identifier, out CancellationTokenSource? signal))
        {
            signal.Cancel();
            signal.Dispose();
        }
    }

    /// <summary>
    /// Creates a cache entry for the specified key.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <param name="resource">The resource to store in the cache entry, if applicable.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    private async ValueTask CreateEntryAsync(object key, TResource? resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        using var entry = _cache.CreateEntry(key);

        if (resource is not null)
        {
            entry.AddExpirationToken(await CreateExpirationSignalAsync(resource, cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0197)));
        }

        entry.Size = 1L;
        entry.Value = resource;
    }

    /// <summary>
    /// Creates a cache entry for the specified key.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <param name="resources">The resources to store in the cache entry.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    private async ValueTask CreateEntryAsync(object key, ImmutableArray<TResource> resources, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        using var entry = _cache.CreateEntry(key);

        foreach (var resource in resources)
        {
            entry.AddExpirationToken(await CreateExpirationSignalAsync(resource, cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0197)));
        }

        entry.Size = resources.Length;
        entry.Value = resources;
    }

    /// <summary>
    /// Creates an expiration signal allowing to invalidate all the
    /// cache entries associated with the specified resource.
    /// </summary>
    /// <param name="resource">The resource associated with the expiration signal.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns an expiration signal for the specified resource.
    /// </returns>
    private async ValueTask<IChangeToken> CreateExpirationSignalAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var identifier = await _store.GetIdAsync(resource, cancellationToken);
        if (string.IsNullOrEmpty(identifier))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0204));
        }

        var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

        return new CancellationChangeToken(signal.Token);
    }
}
