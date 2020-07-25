/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Core
{
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
            [NotNull] IOptionsMonitor<OpenIddictCoreOptions> options,
            [NotNull] IOpenIddictScopeStoreResolver resolver)
        {
            _cache = new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = options.CurrentValue.EntityCacheLimit
            });

            _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
            _store = resolver.Get<TScope>();
        }

        /// <summary>
        /// Add the specified scope to the cache.
        /// </summary>
        /// <param name="scope">The scope to add to the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public async ValueTask AddAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
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

        /// <summary>
        /// Disposes the resources held by this instance.
        /// </summary>
        public void Dispose()
        {
            foreach (var signal in _signals)
            {
                signal.Value.Dispose();
            }

            _cache.Dispose();
        }

        /// <summary>
        /// Retrieves a scope using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the identifier.
        /// </returns>
        public ValueTask<TScope> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
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

            if (_cache.TryGetValue(parameters, out TScope scope))
            {
                return new ValueTask<TScope>(scope);
            }

            async Task<TScope> ExecuteAsync()
            {
                if ((scope = await _store.FindByIdAsync(identifier, cancellationToken)) != null)
                {
                    await AddAsync(scope, cancellationToken);
                }

                await CreateEntryAsync(parameters, scope, cancellationToken);

                return scope;
            }

            return new ValueTask<TScope>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves a scope using its name.
        /// </summary>
        /// <param name="name">The name associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the specified name.
        /// </returns>
        public ValueTask<TScope> FindByNameAsync([NotNull] string name, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1201), nameof(name));
            }

            var parameters = new
            {
                Method = nameof(FindByNameAsync),
                Name = name
            };

            if (_cache.TryGetValue(parameters, out TScope scope))
            {
                return new ValueTask<TScope>(scope);
            }

            async Task<TScope> ExecuteAsync()
            {
                if ((scope = await _store.FindByNameAsync(name, cancellationToken)) != null)
                {
                    await AddAsync(scope, cancellationToken);
                }

                await CreateEntryAsync(parameters, scope, cancellationToken);

                return scope;
            }

            return new ValueTask<TScope>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves a list of scopes using their name.
        /// </summary>
        /// <param name="names">The names associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The scopes corresponding to the specified names.</returns>
        public IAsyncEnumerable<TScope> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
        {
            if (names.Any(name => string.IsNullOrEmpty(name)))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1202), nameof(names));
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

        /// <summary>
        /// Retrieves all the scopes that contain the specified resource.
        /// </summary>
        /// <param name="resource">The resource associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The scopes associated with the specified resource.</returns>
        public IAsyncEnumerable<TScope> FindByResourceAsync([NotNull] string resource, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1061), nameof(resource));
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

        /// <summary>
        /// Removes the specified scope from the cache.
        /// </summary>
        /// <param name="scope">The scope to remove from the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public async ValueTask RemoveAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            var identifier = await _store.GetIdAsync(scope, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1195));
            }

            if (_signals.TryRemove(identifier, out CancellationTokenSource signal))
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
        protected virtual async ValueTask CreateEntryAsync(
            [NotNull] object key, [CanBeNull] TScope scope, CancellationToken cancellationToken)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using var entry = _cache.CreateEntry(key);

            if (scope != null)
            {
                var signal = await CreateExpirationSignalAsync(scope, cancellationToken);
                if (signal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1196));
                }

                entry.AddExpirationToken(signal);
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
            [NotNull] object key, [CanBeNull] ImmutableArray<TScope> scopes, CancellationToken cancellationToken)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using var entry = _cache.CreateEntry(key);

            foreach (var scope in scopes)
            {
                var signal = await CreateExpirationSignalAsync(scope, cancellationToken);
                if (signal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1196));
                }

                entry.AddExpirationToken(signal);
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
        protected virtual async ValueTask<IChangeToken> CreateExpirationSignalAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            var identifier = await _store.GetIdAsync(scope, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1203));
            }

            var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

            return new CancellationChangeToken(signal.Token);
        }
    }
}
