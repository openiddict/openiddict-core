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
/// Provides methods allowing to cache sessions after retrieving them from the store.
/// </summary>
/// <typeparam name="TSession">The type of the Session entity.</typeparam>
public sealed class OpenIddictSessionCache<TSession> : IOpenIddictSessionCache<TSession>, IDisposable where TSession : class
{
    private readonly MemoryCache _cache;
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _signals;
    private readonly IOpenIddictSessionStore<TSession> _store;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictSessionCache{TSession}"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <param name="store">The store.</param>
    public OpenIddictSessionCache(
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictSessionStore<TSession> store)
    {
        _cache = new MemoryCache(new MemoryCacheOptions
        {
            SizeLimit = (options ?? throw new ArgumentNullException(nameof(options))).CurrentValue.EntityCacheLimit
        });

        _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <inheritdoc/>
    public async ValueTask AddAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        _cache.Remove(new
        {
            Method = nameof(FindByApplicationIdAsync),
            Identifier = await _store.GetApplicationIdAsync(session, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindByAuthorizationIdAsync),
            Identifier = await _store.GetAuthorizationIdAsync(session, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(session, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindByLoginIdAsync),
            Identifier = await _store.GetLoginIdAsync(session, cancellationToken)
        });

        _cache.Remove(new
        {
            Method = nameof(FindBySubjectAsync),
            Subject = await _store.GetSubjectAsync(session, cancellationToken)
        });

        await CreateEntryAsync(new
        {
            Method = nameof(FindByIdAsync),
            Identifier = await _store.GetIdAsync(session, cancellationToken)
        }, session, cancellationToken);
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
    public async IAsyncEnumerable<TSession> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? Status) query,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        // Note: this method is only partially cached.

        await foreach (var session in _store.FindAsync(query, cancellationToken))
        {
            await AddAsync(session, cancellationToken);

            yield return session;
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TSession> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindByApplicationIdAsync),
                Identifier = identifier
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TSession> sessions))
            {
                var builder = ImmutableArray.CreateBuilder<TSession>();

                await foreach (var session in _store.FindByApplicationIdAsync(identifier, cancellationToken))
                {
                    builder.Add(session);

                    await AddAsync(session, cancellationToken);
                }

                sessions = builder.ToImmutable();

                await CreateEntryAsync(parameters, sessions, cancellationToken);
            }

            foreach (var session in sessions)
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TSession> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindByAuthorizationIdAsync),
                Identifier = identifier
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TSession> sessions))
            {
                var builder = ImmutableArray.CreateBuilder<TSession>();

                await foreach (var session in _store.FindByAuthorizationIdAsync(identifier, cancellationToken))
                {
                    builder.Add(session);

                    await AddAsync(session, cancellationToken);
                }

                sessions = builder.ToImmutable();

                await CreateEntryAsync(parameters, sessions, cancellationToken);
            }

            foreach (var session in sessions)
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public ValueTask<TSession?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var parameters = new
        {
            Method = nameof(FindByIdAsync),
            Identifier = identifier
        };

        if (_cache.TryGetValue(parameters, out TSession? session))
        {
            return new(session);
        }

        return new(ExecuteAsync());

        async Task<TSession?> ExecuteAsync()
        {
            if ((session = await _store.FindByIdAsync(identifier, cancellationToken)) is not null)
            {
                await AddAsync(session, cancellationToken);
            }

            await CreateEntryAsync(parameters, session, cancellationToken);

            return session;
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TSession> FindByLoginIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindByLoginIdAsync),
                Identifier = identifier
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TSession> sessions))
            {
                var builder = ImmutableArray.CreateBuilder<TSession>();

                await foreach (var session in _store.FindByLoginIdAsync(identifier, cancellationToken))
                {
                    builder.Add(session);

                    await AddAsync(session, cancellationToken);
                }

                sessions = builder.ToImmutable();

                await CreateEntryAsync(parameters, sessions, cancellationToken);
            }

            foreach (var session in sessions)
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public IAsyncEnumerable<TSession> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var parameters = new
            {
                Method = nameof(FindBySubjectAsync),
                Identifier = subject
            };

            if (!_cache.TryGetValue(parameters, out ImmutableArray<TSession> sessions))
            {
                var builder = ImmutableArray.CreateBuilder<TSession>();

                await foreach (var session in _store.FindBySubjectAsync(subject, cancellationToken))
                {
                    builder.Add(session);

                    await AddAsync(session, cancellationToken);
                }

                sessions = builder.ToImmutable();

                await CreateEntryAsync(parameters, sessions, cancellationToken);
            }

            foreach (var session in sessions)
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public async ValueTask RemoveAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var identifier = await _store.GetIdAsync(session, cancellationToken);
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
    /// <param name="session">The session to store in the cache entry, if applicable.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    private async ValueTask CreateEntryAsync(object key, TSession? session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        using var entry = _cache.CreateEntry(key);

        if (session is not null)
        {
            entry.AddExpirationToken(await CreateExpirationSignalAsync(session, cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0197)));
        }

        entry.Size = 1L;
        entry.Value = session;
    }

    /// <summary>
    /// Creates a cache entry for the specified key.
    /// </summary>
    /// <param name="key">The cache key.</param>
    /// <param name="sessions">The sessions to store in the cache entry.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    private async ValueTask CreateEntryAsync(object key, ImmutableArray<TSession> sessions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        using var entry = _cache.CreateEntry(key);

        foreach (var session in sessions)
        {
            entry.AddExpirationToken(await CreateExpirationSignalAsync(session, cancellationToken)
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0197)));
        }

        entry.Size = sessions.Length;
        entry.Value = sessions;
    }

    /// <summary>
    /// Creates an expiration signal allowing to invalidate all the
    /// cache entries associated with the specified session.
    /// </summary>
    /// <param name="session">The session associated with the expiration signal.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns an expiration signal for the specified session.
    /// </returns>
    private async ValueTask<IChangeToken> CreateExpirationSignalAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var identifier = await _store.GetIdAsync(session, cancellationToken);
        if (string.IsNullOrEmpty(identifier))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0204));
        }

        var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

        return new CancellationChangeToken(signal.Token);
    }
}
