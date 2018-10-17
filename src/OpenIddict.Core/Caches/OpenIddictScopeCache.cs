/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to cache scopes after retrieving them from the store.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    public class OpenIddictScopeCache<TScope> : IOpenIddictScopeCache<TScope>, IDisposable where TScope : class
    {
        private readonly IMemoryCache _cache;
        private readonly IOpenIddictScopeStore<TScope> _store;

        public OpenIddictScopeCache(
            [NotNull] IOptionsMonitor<OpenIddictCoreOptions> options,
            [NotNull] IOpenIddictScopeStoreResolver resolver)
        {
            _cache = new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = options.CurrentValue.EntityCacheLimit
            });

            _store = resolver.Get<TScope>();
        }

        /// <summary>
        /// Add the specified scope to the cache.
        /// </summary>
        /// <param name="scope">The scope to add to the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public async Task AddAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            using (var entry = _cache.CreateEntry(new
            {
                Method = nameof(FindByIdAsync),
                Identifier = await _store.GetIdAsync(scope, cancellationToken)
            }))
            {
                entry.SetSize(1L);
                entry.SetValue(scope);
            }

            using (var entry = _cache.CreateEntry(new
            {
                Method = nameof(FindByNameAsync),
                Name = await _store.GetNameAsync(scope, cancellationToken)
            }))
            {
                entry.SetSize(1L);
                entry.SetValue(scope);
            }
        }

        /// <summary>
        /// Disposes the cache held by this instance.
        /// </summary>
        public void Dispose() => _cache.Dispose();

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
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
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

                using (var entry = _cache.CreateEntry(parameters))
                {
                    entry.SetSize(1L);
                    entry.SetValue(scope);
                }

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
                throw new ArgumentException("The scope name cannot be null or empty.", nameof(name));
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

                using (var entry = _cache.CreateEntry(parameters))
                {
                    entry.SetSize(1L);
                    entry.SetValue(scope);
                }

                return scope;
            }

            return new ValueTask<TScope>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves a list of scopes using their name.
        /// </summary>
        /// <param name="names">The names associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes corresponding to the specified names.
        /// </returns>
        public ValueTask<ImmutableArray<TScope>> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
        {
            if (names.IsDefaultOrEmpty)
            {
                return new ValueTask<ImmutableArray<TScope>>(ImmutableArray.Create<TScope>());
            }

            if (names.Any(name => string.IsNullOrEmpty(name)))
            {
                throw new ArgumentException("Scope names cannot be null or empty.", nameof(names));
            }

            // Note: this method is only partially cached.

            async Task<ImmutableArray<TScope>> ExecuteAsync()
            {
                var scopes = await _store.FindByNamesAsync(names, cancellationToken);

                foreach (var scope in scopes)
                {
                    await AddAsync(scope, cancellationToken);
                }

                return scopes;
            }

            return new ValueTask<ImmutableArray<TScope>>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves all the scopes that contain the specified resource.
        /// </summary>
        /// <param name="resource">The resource associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes associated with the specified resource.
        /// </returns>
        public ValueTask<ImmutableArray<TScope>> FindByResourceAsync([NotNull] string resource, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException("The resource cannot be null or empty.", nameof(resource));
            }

            var parameters = new
            {
                Method = nameof(FindByResourceAsync),
                Resource = resource
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TScope> scopes))
            {
                return new ValueTask<ImmutableArray<TScope>>(scopes);
            }

            async Task<ImmutableArray<TScope>> ExecuteAsync()
            {
                foreach (var scope in (scopes = await _store.FindByResourceAsync(resource, cancellationToken)))
                {
                    await AddAsync(scope, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    entry.SetSize(scopes.Length);
                    entry.SetValue(scopes);
                }

                return scopes;
            }

            return new ValueTask<ImmutableArray<TScope>>(ExecuteAsync());
        }

        /// <summary>
        /// Removes the specified scope from the cache.
        /// </summary>
        /// <param name="scope">The scope to remove from the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public async Task RemoveAsync([NotNull] TScope scope, CancellationToken cancellationToken)
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
        }
    }
}
