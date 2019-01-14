/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

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
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public async Task AddAsync([NotNull] TApplication application, CancellationToken cancellationToken)
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

            var signal = await CreateExpirationSignalAsync(application, cancellationToken);
            if (signal == null)
            {
                throw new InvalidOperationException("An error occurred while creating an expiration signal.");
            }

            using (var entry = _cache.CreateEntry(new
            {
                Method = nameof(FindByIdAsync),
                Identifier = await _store.GetIdAsync(application, cancellationToken)
            }))
            {
                entry.AddExpirationToken(signal)
                     .SetSize(1L)
                     .SetValue(application);
            }

            using (var entry = _cache.CreateEntry(new
            {
                Method = nameof(FindByClientIdAsync),
                Identifier = await _store.GetClientIdAsync(application, cancellationToken)
            }))
            {
                entry.AddExpirationToken(signal)
                     .SetSize(1L)
                     .SetValue(application);
            }
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
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
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

            async Task<TApplication> ExecuteAsync()
            {
                if ((application = await _store.FindByClientIdAsync(identifier, cancellationToken)) != null)
                {
                    await AddAsync(application, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    if (application != null)
                    {
                        var signal = await CreateExpirationSignalAsync(application, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(1L);
                    entry.SetValue(application);
                }

                return application;
            }

            return new ValueTask<TApplication>(ExecuteAsync());
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
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
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

            async Task<TApplication> ExecuteAsync()
            {
                if ((application = await _store.FindByIdAsync(identifier, cancellationToken)) != null)
                {
                    await AddAsync(application, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    if (application != null)
                    {
                        var signal = await CreateExpirationSignalAsync(application, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(1L);
                    entry.SetValue(application);
                }

                return application;
            }

            return new ValueTask<TApplication>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
        /// </summary>
        /// <param name="address">The post_logout_redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client applications corresponding to the specified post_logout_redirect_uri.
        /// </returns>
        public ValueTask<ImmutableArray<TApplication>> FindByPostLogoutRedirectUriAsync(
            [NotNull] string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException("The address cannot be null or empty.", nameof(address));
            }

            var parameters = new
            {
                Method = nameof(FindByPostLogoutRedirectUriAsync),
                Address = address
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TApplication> applications))
            {
                return new ValueTask<ImmutableArray<TApplication>>(applications);
            }

            async Task<ImmutableArray<TApplication>> ExecuteAsync()
            {
                foreach (var application in (applications = await _store.FindByPostLogoutRedirectUriAsync(address, cancellationToken)))
                {
                    await AddAsync(application, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var application in applications)
                    {
                        var signal = await CreateExpirationSignalAsync(application, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(applications.Length);
                    entry.SetValue(applications);
                }

                return applications;
            }

            return new ValueTask<ImmutableArray<TApplication>>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified redirect_uri.
        /// </summary>
        /// <param name="address">The redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client applications corresponding to the specified redirect_uri.
        /// </returns>
        public ValueTask<ImmutableArray<TApplication>> FindByRedirectUriAsync(
            [NotNull] string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException("The address cannot be null or empty.", nameof(address));
            }

            var parameters = new
            {
                Method = nameof(FindByRedirectUriAsync),
                Address = address
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TApplication> applications))
            {
                return new ValueTask<ImmutableArray<TApplication>>(applications);
            }

            async Task<ImmutableArray<TApplication>> ExecuteAsync()
            {
                foreach (var application in (applications = await _store.FindByRedirectUriAsync(address, cancellationToken)))
                {
                    await AddAsync(application, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var application in applications)
                    {
                        var signal = await CreateExpirationSignalAsync(application, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(applications.Length);
                    entry.SetValue(applications);
                }

                return applications;
            }

            return new ValueTask<ImmutableArray<TApplication>>(ExecuteAsync());
        }

        /// <summary>
        /// Removes the specified application from the cache.
        /// </summary>
        /// <param name="application">The application to remove from the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public async Task RemoveAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var identifier = await _store.GetIdAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException("The application identifier cannot be extracted.");
            }

            if (_signals.TryGetValue(identifier, out CancellationTokenSource signal))
            {
                signal.Cancel();

                _signals.TryRemove(identifier, out signal);
            }
        }

        /// <summary>
        /// Creates an expiration signal allowing to invalidate all the
        /// cache entries associated with the specified application.
        /// </summary>
        /// <param name="application">The application associated with the expiration signal.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns an expiration signal for the specified application.
        /// </returns>
        protected virtual async Task<IChangeToken> CreateExpirationSignalAsync(
            [NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var identifier = await _store.GetIdAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException("The application identifier cannot be extracted.");
            }

            var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

            return new CancellationChangeToken(signal.Token);
        }
    }
}
