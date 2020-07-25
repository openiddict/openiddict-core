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
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to cache applications after retrieving them from the store.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    public class OpenIddictApplicationCache<TApplication> : IOpenIddictApplicationCache<TApplication>, IDisposable where TApplication : class
    {
        private readonly MemoryCache _cache;
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _signals;
        private readonly IOpenIddictApplicationStore<TApplication> _store;

        public OpenIddictApplicationCache(
            [NotNull] IOptionsMonitor<OpenIddictCoreOptions> options,
            [NotNull] IOpenIddictApplicationStoreResolver resolver)
        {
            _cache = new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = options.CurrentValue.EntityCacheLimit
            });

            _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
            _store = resolver.Get<TApplication>();
        }

        /// <summary>
        /// Add the specified application to the cache.
        /// </summary>
        /// <param name="application">The application to add to the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public async ValueTask AddAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            _cache.Remove(new
            {
                Method = nameof(FindByClientIdAsync),
                Identifier = await _store.GetClientIdAsync(application, cancellationToken)
            });

            _cache.Remove(new
            {
                Method = nameof(FindByIdAsync),
                Identifier = await _store.GetIdAsync(application, cancellationToken)
            });

            foreach (var address in await _store.GetPostLogoutRedirectUrisAsync(application, cancellationToken))
            {
                _cache.Remove(new
                {
                    Method = nameof(FindByPostLogoutRedirectUriAsync),
                    Address = address
                });
            }

            foreach (var address in await _store.GetRedirectUrisAsync(application, cancellationToken))
            {
                _cache.Remove(new
                {
                    Method = nameof(FindByRedirectUriAsync),
                    Address = address
                });
            }

            await CreateEntryAsync(new
            {
                Method = nameof(FindByIdAsync),
                Identifier = await _store.GetIdAsync(application, cancellationToken)
            }, application, cancellationToken);

            await CreateEntryAsync(new
            {
                Method = nameof(FindByClientIdAsync),
                Identifier = await _store.GetClientIdAsync(application, cancellationToken)
            }, application, cancellationToken);
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
        /// Retrieves an application using its client identifier.
        /// </summary>
        /// <param name="identifier">The client identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public ValueTask<TApplication> FindByClientIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            var parameters = new
            {
                Method = nameof(FindByClientIdAsync),
                Identifier = identifier
            };

            if (_cache.TryGetValue(parameters, out TApplication application))
            {
                return new ValueTask<TApplication>(application);
            }

            return new ValueTask<TApplication>(ExecuteAsync());

            async Task<TApplication> ExecuteAsync()
            {
                if ((application = await _store.FindByClientIdAsync(identifier, cancellationToken)) != null)
                {
                    await AddAsync(application, cancellationToken);
                }

                await CreateEntryAsync(parameters, application, cancellationToken);

                return application;
            }
        }

        /// <summary>
        /// Retrieves an application using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public ValueTask<TApplication> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
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

            if (_cache.TryGetValue(parameters, out TApplication application))
            {
                return new ValueTask<TApplication>(application);
            }

            return new ValueTask<TApplication>(ExecuteAsync());

            async Task<TApplication> ExecuteAsync()
            {
                if ((application = await _store.FindByIdAsync(identifier, cancellationToken)) != null)
                {
                    await AddAsync(application, cancellationToken);
                }

                await CreateEntryAsync(parameters, application, cancellationToken);

                return application;
            }
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
        /// </summary>
        /// <param name="address">The post_logout_redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The client applications corresponding to the specified post_logout_redirect_uri.</returns>
        public IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(
            [NotNull] string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1142), nameof(address));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindByPostLogoutRedirectUriAsync),
                    Address = address
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TApplication> applications))
                {
                    var builder = ImmutableArray.CreateBuilder<TApplication>();

                    await foreach (var application in _store.FindByPostLogoutRedirectUriAsync(address, cancellationToken))
                    {
                        builder.Add(application);

                        await AddAsync(application, cancellationToken);
                    }

                    applications = builder.ToImmutable();

                    await CreateEntryAsync(parameters, applications, cancellationToken);
                }

                foreach (var application in applications)
                {
                    yield return application;
                }
            }
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified redirect_uri.
        /// </summary>
        /// <param name="address">The redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The client applications corresponding to the specified redirect_uri.</returns>
        public IAsyncEnumerable<TApplication> FindByRedirectUriAsync(
            [NotNull] string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1142), nameof(address));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var parameters = new
                {
                    Method = nameof(FindByRedirectUriAsync),
                    Address = address
                };

                if (!_cache.TryGetValue(parameters, out ImmutableArray<TApplication> applications))
                {
                    var builder = ImmutableArray.CreateBuilder<TApplication>();

                    await foreach (var application in _store.FindByRedirectUriAsync(address, cancellationToken))
                    {
                        builder.Add(application);

                        await AddAsync(application, cancellationToken);
                    }

                    applications = builder.ToImmutable();

                    await CreateEntryAsync(parameters, applications, cancellationToken);
                }

                foreach (var application in applications)
                {
                    yield return application;
                }
            }
        }

        /// <summary>
        /// Removes the specified application from the cache.
        /// </summary>
        /// <param name="application">The application to remove from the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        public async ValueTask RemoveAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var identifier = await _store.GetIdAsync(application, cancellationToken);
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
        /// <param name="application">The application to store in the cache entry, if applicable.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        protected virtual async ValueTask CreateEntryAsync(
            [NotNull] object key, [CanBeNull] TApplication application, CancellationToken cancellationToken)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using var entry = _cache.CreateEntry(key);

            if (application != null)
            {
                var signal = await CreateExpirationSignalAsync(application, cancellationToken);
                if (signal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1196));
                }

                entry.AddExpirationToken(signal);
            }

            entry.SetSize(1L);
            entry.SetValue(application);
        }

        /// <summary>
        /// Creates a cache entry for the specified key.
        /// </summary>
        /// <param name="key">The cache key.</param>
        /// <param name="applications">The applications to store in the cache entry.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
        protected virtual async ValueTask CreateEntryAsync(
            [NotNull] object key, [CanBeNull] ImmutableArray<TApplication> applications, CancellationToken cancellationToken)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            using var entry = _cache.CreateEntry(key);

            foreach (var application in applications)
            {
                var signal = await CreateExpirationSignalAsync(application, cancellationToken);
                if (signal == null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID1196));
                }

                entry.AddExpirationToken(signal);
            }

            entry.SetSize(applications.Length);
            entry.SetValue(applications);
        }

        /// <summary>
        /// Creates an expiration signal allowing to invalidate all the
        /// cache entries associated with the specified application.
        /// </summary>
        /// <param name="application">The application associated with the expiration signal.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns an expiration signal for the specified application.
        /// </returns>
        protected virtual async ValueTask<IChangeToken> CreateExpirationSignalAsync(
            [NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var identifier = await _store.GetIdAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID1195));
            }

            var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

            return new CancellationChangeToken(signal.Token);
        }
    }
}
