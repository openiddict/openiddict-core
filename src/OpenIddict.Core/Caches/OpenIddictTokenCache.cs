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
    /// Provides methods allowing to cache tokens after retrieving them from the store.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    public class OpenIddictTokenCache<TToken> : IOpenIddictTokenCache<TToken>, IDisposable where TToken : class
    {
        private readonly MemoryCache _cache;
        private readonly ConcurrentDictionary<string, CancellationTokenSource> _signals;
        private readonly IOpenIddictTokenStore<TToken> _store;

        public OpenIddictTokenCache(
            [NotNull] IOptionsMonitor<OpenIddictCoreOptions> options,
            [NotNull] IOpenIddictTokenStoreResolver resolver)
        {
            _cache = new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = options.CurrentValue.EntityCacheLimit
            });

            _signals = new ConcurrentDictionary<string, CancellationTokenSource>(StringComparer.Ordinal);
            _store = resolver.Get<TToken>();
        }

        /// <summary>
        /// Add the specified token to the cache.
        /// </summary>
        /// <param name="token">The token to add to the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public async Task AddAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
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

            var signal = await CreateExpirationSignalAsync(token, cancellationToken);
            if (signal == null)
            {
                throw new InvalidOperationException("An error occurred while creating an expiration signal.");
            }

            using (var entry = _cache.CreateEntry(new
            {
                Method = nameof(FindByIdAsync),
                Identifier = await _store.GetIdAsync(token, cancellationToken)
            }))
            {
                entry.AddExpirationToken(signal)
                     .SetSize(1L)
                     .SetValue(token);
            }

            using (var entry = _cache.CreateEntry(new
            {
                Method = nameof(FindByReferenceIdAsync),
                Identifier = await _store.GetReferenceIdAsync(token, cancellationToken)
            }))
            {
                entry.AddExpirationToken(signal)
                     .SetSize(1L)
                     .SetValue(token);
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
        /// Retrieves the tokens corresponding to the specified
        /// subject and associated with the application identifier.
        /// </summary>
        /// <param name="subject">The subject associated with the token.</param>
        /// <param name="client">The client associated with the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the subject/client.
        /// </returns>
        public ValueTask<ImmutableArray<TToken>> FindAsync([NotNull] string subject,
            [NotNull] string client, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(client));
            }

            var parameters = new
            {
                Method = nameof(FindAsync),
                Subject = subject,
                Client = client
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
            {
                return new ValueTask<ImmutableArray<TToken>>(tokens);
            }

            async Task<ImmutableArray<TToken>> ExecuteAsync()
            {
                foreach (var token in (tokens = await _store.FindAsync(subject, client, cancellationToken)))
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var token in tokens)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(tokens.Length);
                    entry.SetValue(tokens);
                }

                return tokens;
            }

            return new ValueTask<ImmutableArray<TToken>>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves the tokens matching the specified parameters.
        /// </summary>
        /// <param name="subject">The subject associated with the token.</param>
        /// <param name="client">The client associated with the token.</param>
        /// <param name="status">The token status.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the criteria.
        /// </returns>
        public ValueTask<ImmutableArray<TToken>> FindAsync(
            [NotNull] string subject, [NotNull] string client,
            [NotNull] string status, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException("The status cannot be null or empty.", nameof(status));
            }

            var parameters = new
            {
                Method = nameof(FindAsync),
                Subject = subject,
                Client = client,
                Status = status
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
            {
                return new ValueTask<ImmutableArray<TToken>>(tokens);
            }

            async Task<ImmutableArray<TToken>> ExecuteAsync()
            {
                foreach (var token in (tokens = await _store.FindAsync(subject, client, status, cancellationToken)))
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var token in tokens)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(tokens.Length);
                    entry.SetValue(tokens);
                }

                return tokens;
            }

            return new ValueTask<ImmutableArray<TToken>>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves the tokens matching the specified parameters.
        /// </summary>
        /// <param name="subject">The subject associated with the token.</param>
        /// <param name="client">The client associated with the token.</param>
        /// <param name="status">The token status.</param>
        /// <param name="type">The token type.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the criteria.
        /// </returns>
        public ValueTask<ImmutableArray<TToken>> FindAsync(
            [NotNull] string subject, [NotNull] string client,
            [NotNull] string status, [NotNull] string type, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException("The status cannot be null or empty.", nameof(status));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The type cannot be null or empty.", nameof(type));
            }

            var parameters = new
            {
                Method = nameof(FindAsync),
                Subject = subject,
                Client = client,
                Status = status,
                Type = type
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
            {
                return new ValueTask<ImmutableArray<TToken>>(tokens);
            }

            async Task<ImmutableArray<TToken>> ExecuteAsync()
            {
                foreach (var token in (tokens = await _store.FindAsync(subject, client, status, type, cancellationToken)))
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var token in tokens)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(tokens.Length);
                    entry.SetValue(tokens);
                }

                return tokens;
            }

            return new ValueTask<ImmutableArray<TToken>>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified application identifier.
        /// </summary>
        /// <param name="identifier">The application identifier associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified application.
        /// </returns>
        public ValueTask<ImmutableArray<TToken>> FindByApplicationIdAsync(
            [NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var parameters = new
            {
                Method = nameof(FindByApplicationIdAsync),
                Identifier = identifier
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
            {
                return new ValueTask<ImmutableArray<TToken>>(tokens);
            }

            async Task<ImmutableArray<TToken>> ExecuteAsync()
            {
                foreach (var token in (tokens = await _store.FindByApplicationIdAsync(identifier, cancellationToken)))
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var token in tokens)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(tokens.Length);
                    entry.SetValue(tokens);
                }

                return tokens;
            }

            return new ValueTask<ImmutableArray<TToken>>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified authorization identifier.
        /// </summary>
        /// <param name="identifier">The authorization identifier associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified authorization.
        /// </returns>
        public ValueTask<ImmutableArray<TToken>> FindByAuthorizationIdAsync(
            [NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var parameters = new
            {
                Method = nameof(FindByAuthorizationIdAsync),
                Identifier = identifier
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
            {
                return new ValueTask<ImmutableArray<TToken>>(tokens);
            }

            async Task<ImmutableArray<TToken>> ExecuteAsync()
            {
                foreach (var token in (tokens = await _store.FindByAuthorizationIdAsync(identifier, cancellationToken)))
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var token in tokens)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(tokens.Length);
                    entry.SetValue(tokens);
                }

                return tokens;
            }

            return new ValueTask<ImmutableArray<TToken>>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves a token using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the token corresponding to the unique identifier.
        /// </returns>
        public ValueTask<TToken> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
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

            if (_cache.TryGetValue(parameters, out TToken token))
            {
                return new ValueTask<TToken>(token);
            }

            async Task<TToken> ExecuteAsync()
            {
                if ((token = await _store.FindByIdAsync(identifier, cancellationToken)) != null)
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    if (token != null)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(1L);
                    entry.SetValue(token);
                }

                return token;
            }

            return new ValueTask<TToken>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified reference identifier.
        /// Note: the reference identifier may be hashed or encrypted for security reasons.
        /// </summary>
        /// <param name="identifier">The reference identifier associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified reference identifier.
        /// </returns>
        public ValueTask<TToken> FindByReferenceIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var parameters = new
            {
                Method = nameof(FindByReferenceIdAsync),
                Identifier = identifier
            };

            if (_cache.TryGetValue(parameters, out TToken token))
            {
                return new ValueTask<TToken>(token);
            }

            async Task<TToken> ExecuteAsync()
            {
                if ((token = await _store.FindByReferenceIdAsync(identifier, cancellationToken)) != null)
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    if (token != null)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(1L);
                    entry.SetValue(token);
                }

                return token;
            }

            return new ValueTask<TToken>(ExecuteAsync());
        }

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified subject.
        /// </summary>
        /// <param name="subject">The subject associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified subject.
        /// </returns>
        public ValueTask<ImmutableArray<TToken>> FindBySubjectAsync([NotNull] string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            var parameters = new
            {
                Method = nameof(FindBySubjectAsync),
                Identifier = subject
            };

            if (_cache.TryGetValue(parameters, out ImmutableArray<TToken> tokens))
            {
                return new ValueTask<ImmutableArray<TToken>>(tokens);
            }

            async Task<ImmutableArray<TToken>> ExecuteAsync()
            {
                foreach (var token in (tokens = await _store.FindBySubjectAsync(subject, cancellationToken)))
                {
                    await AddAsync(token, cancellationToken);
                }

                using (var entry = _cache.CreateEntry(parameters))
                {
                    foreach (var token in tokens)
                    {
                        var signal = await CreateExpirationSignalAsync(token, cancellationToken);
                        if (signal == null)
                        {
                            throw new InvalidOperationException("An error occurred while creating an expiration signal.");
                        }

                        entry.AddExpirationToken(signal);
                    }

                    entry.SetSize(tokens.Length);
                    entry.SetValue(tokens);
                }

                return tokens;
            }

            return new ValueTask<ImmutableArray<TToken>>(ExecuteAsync());
        }

        /// <summary>
        /// Removes the specified token from the cache.
        /// </summary>
        /// <param name="token">The token to remove from the cache.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public async Task RemoveAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var identifier = await _store.GetIdAsync(token, cancellationToken);
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
        /// cache entries associated with the specified token.
        /// </summary>
        /// <param name="token">The token associated with the expiration signal.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns an expiration signal for the specified token.
        /// </returns>
        protected virtual async Task<IChangeToken> CreateExpirationSignalAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var identifier = await _store.GetIdAsync(token, cancellationToken);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException("The token identifier cannot be extracted.");
            }

            var signal = _signals.GetOrAdd(identifier, _ => new CancellationTokenSource());

            return new CancellationChangeToken(signal.Token);
        }
    }
}
