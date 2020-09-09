/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to cache tokens after retrieving them from the store.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    public class OpenIddictTokenCache<TToken> : IOpenIddictTokenCache<TToken>, IDisposable where TToken : class
    {
        private readonly MemoryCache _cache;
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _signals;
        private readonly IOpenIddictTokenStore<TToken> _store;

        public OpenIddictTokenCache(
            IOptionsMonitor<OpenIddictCoreOptions> options,
            IOpenIddictTokenStoreResolver resolver)
        {
            _cache = new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = options.CurrentValue.EntityCacheLimit
            });

            _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
            _store = resolver.Get<TToken>();
        }

        /// <inheritdoc/>
        public async ValueTask AddAsync(TToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            _cache.Remove(new
            {
                Method = nameof(FindAsync),
                Subject = await _store.GetSubjectAsync(token, cancellationToken),
                Client = await _store.GetApplicationIdAsync(token, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindAsync),
                Subject = await _store.GetSubjectAsync(token, cancellationToken),
                Client = await _store.GetApplicationIdAsync(token, cancellationToken),
                Status = await _store.GetStatusAsync(token, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindAsync),
                Subject = await _store.GetSubjectAsync(token, cancellationToken),
                Client = await _store.GetApplicationIdAsync(token, cancellationToken),
                Status = await _store.GetStatusAsync(token, cancellationToken),
                Type = await _store.GetTypeAsync(token, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindByApplicationIdAsync),
                Identifier = await _store.GetApplicationIdAsync(token, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindByAuthorizationIdAsync),
                Identifier = await _store.GetAuthorizationIdAsync(token, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindByIdAsync),
                Identifier = await _store.GetIdAsync(token, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindByReferenceIdAsync),
                Identifier = await _store.GetReferenceIdAsync(token, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindBySubjectAsync),
                Subject = await _store.GetSubjectAsync(token, cancellationToken)
            });

            await CreateEntryAsync(new
            {
                Method = nameof(FindByIdAsync),
                Identifier = await _store.GetIdAsync(token, cancellationToken)
            }, token, cancellationToken);

            await CreateEntryAsync(new
            {
                Method = nameof(FindByReferenceIdAsync),
                Identifier = await _store.GetReferenceIdAsync(token, cancellationToken)
            }, token, cancellationToken);
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
        public IAsyncEnumerable<TToken> FindAsync(string subject, string client, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1197), nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1123), nameof(client));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindAsync),
                    Subject = subject,
                    Client = client
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
                {
                    var builder = ImmutableArray.CreateBuilder<TToken>();

                    await foreach (var token in _store.FindAsync(subject, client, cancellationToken))
                    {
                        builder.Add(token);

                        await AddAsync(token, cancellationToken);
                    }

                    tokens = builder.ToImmutable();

                    await CreateEntryAsync(parameters, tokens, cancellationToken);
                }

                foreach (var token in tokens)
                {
                    yield return token;
                }
            }
        }

        /// <inheritdoc/>
        public IAsyncEnumerable<TToken> FindAsync(
            string subject, string client,
            string status, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1197), nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1123), nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1198), nameof(status));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindAsync),
                    Subject = subject,
                    Client = client,
                    Status = status
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
                {
                    var builder = ImmutableArray.CreateBuilder<TToken>();

                    await foreach (var token in _store.FindAsync(subject, client, status, cancellationToken))
                    {
                        builder.Add(token);

                        await AddAsync(token, cancellationToken);
                    }

                    tokens = builder.ToImmutable();

                    await CreateEntryAsync(parameters, tokens, cancellationToken);
                }

                foreach (var token in tokens)
                {
                    yield return token;
                }
            }
        }

        /// <inheritdoc/>
        public IAsyncEnumerable<TToken> FindAsync(
            string subject, string client,
            string status, string type, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1197), nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1123), nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1198), nameof(status));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1199), nameof(type));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindAsync),
                    Subject = subject,
                    Client = client,
                    Status = status,
                    Type = type
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
                {
                    var builder = ImmutableArray.CreateBuilder<TToken>();

                    await foreach (var token in _store.FindAsync(subject, client, status, type, cancellationToken))
                    {
                        builder.Add(token);

                        await AddAsync(token, cancellationToken);
                    }

                    tokens = builder.ToImmutable();

                    await CreateEntryAsync(parameters, tokens, cancellationToken);
                }

                foreach (var token in tokens)
                {
                    yield return token;
                }
            }
        }

        /// <inheritdoc/>
        public IAsyncEnumerable<TToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindByApplicationIdAsync),
                    Identifier = identifier
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
                {
                    var builder = ImmutableArray.CreateBuilder<TToken>();

                    await foreach (var token in _store.FindByApplicationIdAsync(identifier, cancellationToken))
                    {
                        builder.Add(token);

                        await AddAsync(token, cancellationToken);
                    }

                    tokens = builder.ToImmutable();

                    await CreateEntryAsync(parameters, tokens, cancellationToken);
                }

                foreach (var token in tokens)
                {
                    yield return token;
                }
            }
        }

        /// <inheritdoc/>
        public IAsyncEnumerable<TToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindByAuthorizationIdAsync),
                    Identifier = identifier
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
                {
                    var builder = ImmutableArray.CreateBuilder<TToken>();

                    await foreach (var token in _store.FindByAuthorizationIdAsync(identifier, cancellationToken))
                    {
                        builder.Add(token);

                        await AddAsync(token, cancellationToken);
                    }

                    tokens = builder.ToImmutable();

                    await CreateEntryAsync(parameters, tokens, cancellationToken);
                }

                foreach (var token in tokens)
                {
                    yield return token;
                }
            }
        }

        /// <inheritdoc/>
        public ValueTask<TToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            var parameters = new
            {
                Method = nameof(FindByIdAsync),
                Identifier = identifier
            };

            if (_cache.TryGetValue(parameters, out TToken? token))
            {
                return new ValueTask<TToken?>(token);
            }

            return new ValueTask<TToken?>(ExecuteAsync());

            async Task<TToken?> ExecuteAsync()
            {
                if ((token = await _store.FindByIdAsync(identifier, cancellationToken)) is not null)
                {
                    await AddAsync(token, cancellationToken);
                }

                await CreateEntryAsync(parameters, token, cancellationToken);

                return token;
            }
        }

        /// <inheritdoc/>
        public ValueTask<TToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            var parameters = new
            {
                Method = nameof(FindByReferenceIdAsync),
                Identifier = identifier
            };

            if (_cache.TryGetValue(parameters, out TToken? token))
            {
                return new ValueTask<TToken?>(token);
            }

            return new ValueTask<TToken?>(ExecuteAsync());

            async Task<TToken?> ExecuteAsync()
            {
                if ((token = await _store.FindByReferenceIdAsync(identifier, cancellationToken)) is not null)
                {
                    await AddAsync(token, cancellationToken);
                }

                await CreateEntryAsync(parameters, token, cancellationToken);

                return token;
            }
        }

        /// <inheritdoc/>
        public IAsyncEnumerable<TToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1197), nameof(subject));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindBySubjectAsync),
                    Identifier = subject
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
                {
                    var builder = ImmutableArray.CreateBuilder<TToken>();

                    await foreach (var token in _store.FindBySubjectAsync(subject, cancellationToken))
                    {
                        builder.Add(token);

                        await AddAsync(token, cancellationToken);
                    }

                    tokens = builder.ToImmutable();

                    await CreateEntryAsync(parameters, tokens, cancellationToken);
                }

                foreach (var token in tokens)
                {
                    yield return token;
                }
            }
        }

        /// <inheritdoc/>
        public async ValueTask RemoveAsync(TToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var identifier = await _store.GetIdAsync(token, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1204));
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
        /// <param name="token">The token to store in the cache entry, if applicable.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        protected virtual async ValueTask CreateEntryAsync(object key, TToken? token, CancellationToken cancellationToken)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using var entry = _cache.CreateEntry(key);

            if (token is not null)
            {
                var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                if (signal is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1196));
                }

                entry.AddExpirationToken(signal);
            }

            entry.SetSize(1L);
            entry.SetValue(token);
        }

        /// <summary>
        /// Creates a cache entry for the specified key.
        /// </summary>
        /// <param name="key">The cache key.</param>
        /// <param name="tokens">The tokens to store in the cache entry.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        protected virtual async ValueTask CreateEntryAsync(
            object key, ImmutableArray<TToken> tokens, CancellationToken cancellationToken)
        {
            if (key is null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using var entry = _cache.CreateEntry(key);

            foreach (var token in tokens)
            {
                var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                if (signal is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1196));
                }

                entry.AddExpirationToken(signal);
            }

            entry.SetSize(tokens.Length);
            entry.SetValue(tokens);
        }

        /// <summary>
        /// Creates an expiration signal allowing to invalidate all the
        /// cache entries associated with the specified token.
        /// </summary>
        /// <param name="token">The token associated with the expiration signal.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns an expiration signal for the specified token.
        /// </returns>
        protected virtual async ValueTask<IChangeToken> CreateExpirationSignalAsync(TToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var identifier = await _store.GetIdAsync(token, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1204));
            }

            var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

            return new CancellationChangeToken(signal.Token);
        }
    }
}
