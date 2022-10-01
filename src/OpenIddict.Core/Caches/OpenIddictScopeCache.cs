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
/// Provides methods allowing to cache scopes after retrieving them from the store.
/// </summary>
/// <typeparam name="TScope">The type of the Scope entity.</typeparam>
public class OpenIddictScopeCache<TScope> : IOpenIddictScopeCache<TScope>, IDisposable where TScope : class
{
    private readonly MemoryCache _cache;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _signals;
    private readonly IOpenIddictScopeStore<TScope> _store;

    public OpenIddictScopeCache(
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictScopeStoreResolver resolver)
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = (options ?? throw new ArgumentNullException(nameof(options))).CurrentValue.EntityCacheLimit
        });

        _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
        _store = (resolver ?? throw new ArgumentNullException(nameof(resolver))).Get<TScope>();
    }

    /// <inheritdoc/>
    public async ValueTask AddAsync(TScope scope, CancellationToken cancellationToken)
    {
        if (scope is null)
        {
            throw new ArgumentNullException(nameof(scope));
        }

        _cache.Remove(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(scope, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindByNameAsync),
            Name = await _store.GetNameAsync(scope, cancellationToken)
        });

        foreach (var resource in await _store.GetResourcesAsync(scope, cancellationToken))
        {
            _cache.Remove(new
            {
                Method = nameof(FindByResourceAsync),
                Resource = resource
            });
        }

        await CreateEntryAsync(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(scope, cancellationToken)
        }, scope, cancellationToken);

        await CreateEntryAsync(new
        {
            Method = nameof(FindByNameAsync),
            Name = await _store.GetNameAsync(scope, cancellationToken)
        }, scope, cancellationToken);
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
    public ValueTask<TScope?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var parameters = new
        {
            Method = nameof(FindByIdAsync),
            Identifier = identifier
        };

        if (_cache.TryGetValue(parameters, out TScope? scope))
        {
            return new(scope);
        }

        return new(ExecuteAsync());

        async Task<TScope?> ExecuteAsync()
        {
            if ((scope = await _store.FindByIdAsync(identifier, cancellationToken)) is not null)
            {
                await AddAsync(scope, cancellationToken);
            }

            await CreateEntryAsync(parameters, scope, cancellationToken);

            return scope;
        }
    }

    /// <inheritdoc/>
    public ValueTask<TScope?> FindByNameAsync(string name, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0202), nameof(name));
        }

        var parameters = new
        {
            Method = nameof(FindByNameAsync),
            Name = name
        };

        if (_cache.TryGetValue(parameters, out TScope? scope))
        {
            return new(scope);
        }

        async Task<TScope?> ExecuteAsync()
        {
            if ((scope = await _store.FindByNameAsync(name, cancellationToken)) is not null)
            {
                await AddAsync(scope, cancellationToken);
            }

            await CreateEntryAsync(parameters, scope, cancellationToken);

            return scope;
        }

        return new(ExecuteAsync());
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TScope> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
    {
        if (names.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0203), nameof(names));
        }

        // Note: this method is only partially cached.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var scope in _store.FindByNamesAsync(names, cancellationToken))
            {
                await AddAsync(scope, cancellationToken);

                yield return scope;
            }
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TScope> FindByResourceAsync(string resource, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(resource))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindByResourceAsync),
                Resource = resource
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TScope> scopes))
            {
                var builder = ImmutableArray.CreateBuilder<TScope>();

                await foreach (var scope in _store.FindByResourceAsync(resource, cancellationToken))
                {
                    builder.Add(scope);

                    await AddAsync(scope, cancellationToken);
                }

                scopes = builder.ToImmutable();

                await CreateEntryAsync(parameters, scopes, cancellationToken);
            }

            foreach (var scope in scopes)
            {
                yield return scope;
            }
        }
    }

    /// <inheritdoc/>
    public async ValueTask RemoveAsync(TScope scope, CancellationToken cancellationToken)
    {
        if (scope is null)
        {
            throw new ArgumentNullException(nameof(scope));
        }

        var identifier = await _store.GetIdAsync(scope, cancellationToken);
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
    /// <param name="scope">The scope to store in the cache entry, if applicable.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    protected virtual async ValueTask CreateEntryAsync(object key, TScope? scope, CancellationToken cancellationToken)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        using var entry = _cache.CreateEntry(key);

        if (scope is not null)
        {
            entry.AddExpirationToken(await CreateExpirationSignalAsync(scope, cancellationToken) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0197)));
        }

        entry.SetSize(1L);
        entry.SetValue(scope);
    }

    /// <summary>
    /// Creates a cache entry for the specified key.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <param name="scopes">The scopes to store in the cache entry.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    protected virtual async ValueTask CreateEntryAsync(
        object key, ImmutableArray<TScope> scopes, CancellationToken cancellationToken)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        using var entry = _cache.CreateEntry(key);

        foreach (var scope in scopes)
        {
            entry.AddExpirationToken(await CreateExpirationSignalAsync(scope, cancellationToken) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0197)));
        }

        entry.SetSize(scopes.Length);
        entry.SetValue(scopes);
    }

    /// <summary>
    /// Creates an expiration signal allowing to invalidate all the
    /// cache entries associated with the specified scope.
    /// </summary>
    /// <param name="scope">The scope associated with the expiration signal.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns an expiration signal for the specified scope.
    /// </returns>
    protected virtual async ValueTask<IChangeToken> CreateExpirationSignalAsync(TScope scope, CancellationToken cancellationToken)
    {
        if (scope is null)
        {
            throw new ArgumentNullException(nameof(scope));
        }

        var identifier = await _store.GetIdAsync(scope, cancellationToken);
        if (string.IsNullOrEmpty(identifier))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0204));
        }

        var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

        return new CancellationChangeToken(signal.Token);
    }
}
