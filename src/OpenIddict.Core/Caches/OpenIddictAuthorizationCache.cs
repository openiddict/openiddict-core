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
/// Provides methods allowing to cache authorizations after retrieving them from the store.
/// </summary>
/// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
public class OpenIddictAuthorizationCache<TAuthorization> : IOpenIddictAuthorizationCache<TAuthorization>, IDisposable where TAuthorization : class
{
    private readonly MemoryCache _cache;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _signals;
    private readonly IOpenIddictAuthorizationStore<TAuthorization> _store;

    public OpenIddictAuthorizationCache(
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictAuthorizationStoreResolver resolver)
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = options.CurrentValue.EntityCacheLimit
        });

        _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
        _store = resolver.Get<TAuthorization>();
    }

    /// <inheritdoc/>
    public async ValueTask AddAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        _cache.Remove(new
        {
            Method = nameof(FindAsync),
            Subject = await _store.GetSubjectAsync(authorization, cancellationToken),
            Client = await _store.GetApplicationIdAsync(authorization, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindAsync),
            Subject = await _store.GetSubjectAsync(authorization, cancellationToken),
            Client = await _store.GetApplicationIdAsync(authorization, cancellationToken),
            Status = await _store.GetStatusAsync(authorization, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindAsync),
            Subject = await _store.GetSubjectAsync(authorization, cancellationToken),
            Client = await _store.GetApplicationIdAsync(authorization, cancellationToken),
            Status = await _store.GetStatusAsync(authorization, cancellationToken),
            Type = await _store.GetTypeAsync(authorization, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindByApplicationIdAsync),
            Identifier = await _store.GetApplicationIdAsync(authorization, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(authorization, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindBySubjectAsync),
            Subject = await _store.GetSubjectAsync(authorization, cancellationToken)
        });

        await CreateEntryAsync(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(authorization, cancellationToken)
        }, authorization, cancellationToken);
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
    public IAsyncEnumerable<TAuthorization> FindAsync(string subject, string client, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindAsync),
                Subject = subject,
                Client = client
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TAuthorization> authorizations))
            {
                var builder = ImmutableArray.CreateBuilder<TAuthorization>();

                await foreach (var authorization in _store.FindAsync(subject, client, cancellationToken))
                {
                    builder.Add(authorization);

                    await AddAsync(authorization, cancellationToken);
                }

                authorizations = builder.ToImmutable();

                await CreateEntryAsync(parameters, authorizations, cancellationToken);
            }

            foreach (var authorization in authorizations)
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TAuthorization> FindAsync(
        string subject, string client,
        string status, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindAsync),
                Subject = subject,
                Client = client,
                Status = status
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TAuthorization> authorizations))
            {
                var builder = ImmutableArray.CreateBuilder<TAuthorization>();

                await foreach (var authorization in _store.FindAsync(subject, client, status, cancellationToken))
                {
                    builder.Add(authorization);

                    await AddAsync(authorization, cancellationToken);
                }

                authorizations = builder.ToImmutable();

                await CreateEntryAsync(parameters, authorizations, cancellationToken);
            }

            foreach (var authorization in authorizations)
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TAuthorization> FindAsync(
        string subject, string client,
        string status, string type, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindAsync),
                Subject = subject,
                Client = client,
                Status = status,
                Type = type
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TAuthorization> authorizations))
            {
                var builder = ImmutableArray.CreateBuilder<TAuthorization>();

                await foreach (var authorization in _store.FindAsync(subject, client, status, type, cancellationToken))
                {
                    builder.Add(authorization);

                    await AddAsync(authorization, cancellationToken);
                }

                authorizations = builder.ToImmutable();

                await CreateEntryAsync(parameters, authorizations, cancellationToken);
            }

            foreach (var authorization in authorizations)
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TAuthorization> FindAsync(
        string subject, string client,
        string status, string type,
        ImmutableArray<string> scopes, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        if (string.IsNullOrEmpty(client))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
        }

        if (string.IsNullOrEmpty(status))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
        }

        // Note: this method is only partially cached.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var authorization in _store.FindAsync(subject, client, status, type, scopes, cancellationToken))
            {
                await AddAsync(authorization, cancellationToken);

                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TAuthorization> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindByApplicationIdAsync),
                Identifier = identifier
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TAuthorization> authorizations))
            {
                var builder = ImmutableArray.CreateBuilder<TAuthorization>();

                await foreach (var authorization in _store.FindByApplicationIdAsync(identifier, cancellationToken))
                {
                    builder.Add(authorization);

                    await AddAsync(authorization, cancellationToken);
                }

                authorizations = builder.ToImmutable();

                await CreateEntryAsync(parameters, authorizations, cancellationToken);
            }

            foreach (var authorization in authorizations)
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public ValueTask<TAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
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

        if (_cache.TryGetValue(parameters, out TAuthorization? authorization))
        {
            return new ValueTask<TAuthorization?>(authorization);
        }

        return new ValueTask<TAuthorization?>(ExecuteAsync());

        async Task<TAuthorization?> ExecuteAsync()
        {
            if ((authorization = await _store.FindByIdAsync(identifier, cancellationToken)) is not null)
            {
                await AddAsync(authorization, cancellationToken);
            }

            await CreateEntryAsync(parameters, authorization, cancellationToken);

            return authorization;
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TAuthorization> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindBySubjectAsync),
                Subject = subject
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TAuthorization> authorizations))
            {
                var builder = ImmutableArray.CreateBuilder<TAuthorization>();

                await foreach (var authorization in _store.FindBySubjectAsync(subject, cancellationToken))
                {
                    builder.Add(authorization);

                    await AddAsync(authorization, cancellationToken);
                }

                authorizations = builder.ToImmutable();

                await CreateEntryAsync(parameters, authorizations, cancellationToken);
            }

            foreach (var authorization in authorizations)
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public async ValueTask RemoveAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var identifier = await _store.GetIdAsync(authorization, cancellationToken);
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
    /// <param name="authorization">The authorization to store in the cache entry, if applicable.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    protected virtual async ValueTask CreateEntryAsync(object key, TAuthorization? authorization, CancellationToken cancellationToken)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        using var entry = _cache.CreateEntry(key);

        if (authorization is not null)
        {
            var signal = await CreateExpirationSignalAsync(authorization, cancellationToken);
            if (signal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0197));
            }

            entry.AddExpirationToken(signal);
        }

        entry.SetSize(1L);
        entry.SetValue(authorization);
    }

    /// <summary>
    /// Creates a cache entry for the specified key.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <param name="authorizations">The authorizations to store in the cache entry.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    protected virtual async ValueTask CreateEntryAsync(
        object key, ImmutableArray<TAuthorization> authorizations, CancellationToken cancellationToken)
    {
        if (key is null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        using var entry = _cache.CreateEntry(key);

        foreach (var authorization in authorizations)
        {
            var signal = await CreateExpirationSignalAsync(authorization, cancellationToken);
            if (signal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0197));
            }

            entry.AddExpirationToken(signal);
        }

        entry.SetSize(authorizations.Length);
        entry.SetValue(authorizations);
    }

    /// <summary>
    /// Creates an expiration signal allowing to invalidate all the
    /// cache entries associated with the specified authorization.
    /// </summary>
    /// <param name="authorization">The authorization associated with the expiration signal.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns an expiration signal for the specified authorization.
    /// </returns>
    protected virtual async ValueTask<IChangeToken> CreateExpirationSignalAsync(
        TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var identifier = await _store.GetIdAsync(authorization, cancellationToken);
        if (string.IsNullOrEmpty(identifier))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0201));
        }

        var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

        return new CancellationChangeToken(signal.Token);
    }
}
