/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using OpenIddict.Models;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to manage the tokens stored in a database.
    /// Note: this base class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public abstract class OpenIddictTokenStore<TToken, TApplication, TAuthorization, TKey> : IOpenIddictTokenStore<TToken>
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>, new()
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>, new()
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>, new()
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Determines the number of tokens that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of applications in the database.
        /// </returns>
        public virtual Task<long> CountAsync(CancellationToken cancellationToken)
        {
            return CountAsync(tokens => tokens, cancellationToken);
        }

        /// <summary>
        /// Determines the number of tokens that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of tokens that match the specified query.
        /// </returns>
        public abstract Task<long> CountAsync<TResult>([NotNull] Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken);

        /// <summary>
        /// Creates a new token.
        /// </summary>
        /// <param name="token">The token to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the token.
        /// </returns>
        public abstract Task<TToken> CreateAsync([NotNull] TToken token, CancellationToken cancellationToken);

        /// <summary>
        /// Creates a new token.
        /// </summary>
        /// <param name="descriptor">The token descriptor.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the token.
        /// </returns>
        public abstract Task<TToken> CreateAsync([NotNull] OpenIddictTokenDescriptor descriptor, CancellationToken cancellationToken);

        /// <summary>
        /// Removes a token.
        /// </summary>
        /// <param name="token">The token to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public abstract Task DeleteAsync([NotNull] TToken token, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified application identifier.
        /// </summary>
        /// <param name="identifier">The application identifier associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified application.
        /// </returns>
        public virtual Task<ImmutableArray<TToken>> FindByApplicationIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            IQueryable<TToken> Query(IQueryable<TToken> tokens)
            {
                var key = ConvertIdentifierFromString(identifier);

                return from token in tokens
                       where token.Application != null
                       where token.Application.Id.Equals(key)
                       select token;
            }

            return ListAsync(Query, cancellationToken);
        }

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified authorization identifier.
        /// </summary>
        /// <param name="identifier">The authorization identifier associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified authorization.
        /// </returns>
        public virtual Task<ImmutableArray<TToken>> FindByAuthorizationIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            IQueryable<TToken> Query(IQueryable<TToken> tokens)
            {
                var key = ConvertIdentifierFromString(identifier);

                return from token in tokens
                       where token.Authorization != null
                       where token.Authorization.Id.Equals(key)
                       select token;
            }

            return ListAsync(Query, cancellationToken);
        }

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified hash.
        /// </summary>
        /// <param name="hash">The hashed crypto-secure random identifier associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified hash.
        /// </returns>
        public virtual Task<TToken> FindByHashAsync([NotNull] string hash, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(hash))
            {
                throw new ArgumentException("The hash cannot be null or empty.", nameof(hash));
            }

            IQueryable<TToken> Query(IQueryable<TToken> tokens)
            {
                return from token in tokens
                       where token.Hash == hash
                       select token;
            }

            return GetAsync(Query, cancellationToken);
        }

        /// <summary>
        /// Retrieves an token using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the token corresponding to the unique identifier.
        /// </returns>
        public virtual Task<TToken> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            IQueryable<TToken> Query(IQueryable<TToken> tokens)
            {
                var key = ConvertIdentifierFromString(identifier);

                return from token in tokens
                       where token.Id.Equals(key)
                       select token;
            }

            return GetAsync(Query, cancellationToken);
        }

        /// <summary>
        /// Retrieves the list of tokens corresponding to the specified subject.
        /// </summary>
        /// <param name="subject">The subject associated with the tokens.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens corresponding to the specified subject.
        /// </returns>
        public virtual Task<ImmutableArray<TToken>> FindBySubjectAsync([NotNull] string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.", nameof(subject));
            }

            IQueryable<TToken> Query(IQueryable<TToken> tokens)
            {
                return from token in tokens
                       where token.Subject == subject
                       select token;
            }

            return ListAsync(Query, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the single element returned when executing the specified query.
        /// </returns>
        public abstract Task<TResult> GetAsync<TResult>([NotNull] Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the optional application identifier associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the application identifier associated with the token.
        /// </returns>
        public virtual async Task<string> GetApplicationIdAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (token.Application != null)
            {
                return ConvertIdentifierToString(token.Application.Id);
            }

            var key = await GetAsync(tokens =>
                from element in tokens
                where element.Id.Equals(token.Id)
                select element.Application.Id, cancellationToken);

            return ConvertIdentifierToString(key);
        }

        /// <summary>
        /// Retrieves the optional authorization identifier associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the authorization identifier associated with the token.
        /// </returns>
        public virtual async Task<string> GetAuthorizationIdAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (token.Authorization != null)
            {
                return ConvertIdentifierToString(token.Authorization.Id);
            }

            var key = await GetAsync(tokens =>
                from element in tokens
                where element.Id.Equals(token.Id)
                select element.Authorization.Id, cancellationToken);

            return ConvertIdentifierToString(key);
        }

        /// <summary>
        /// Retrieves the ciphertext associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the ciphertext associated with the specified token.
        /// </returns>
        public virtual Task<string> GetCiphertextAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(token.Ciphertext);
        }

        /// <summary>
        /// Retrieves the creation date associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the creation date associated with the specified token.
        /// </returns>
        public virtual Task<DateTimeOffset?> GetCreationDateAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(token.CreationDate);
        }

        /// <summary>
        /// Retrieves the expiration date associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the expiration date associated with the specified token.
        /// </returns>
        public virtual Task<DateTimeOffset?> GetExpirationDateAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(token.ExpirationDate);
        }

        /// <summary>
        /// Retrieves the hashed identifier associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the hashed identifier associated with the specified token.
        /// </returns>
        public virtual Task<string> GetHashAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(token.Hash);
        }

        /// <summary>
        /// Retrieves the unique identifier associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        public virtual Task<string> GetIdAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(ConvertIdentifierToString(token.Id));
        }

        /// <summary>
        /// Retrieves the status associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the status associated with the specified token.
        /// </returns>
        public virtual Task<string> GetStatusAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(token.Status);
        }

        /// <summary>
        /// Retrieves the subject associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the subject associated with the specified token.
        /// </returns>
        public virtual Task<string> GetSubjectAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(token.Subject);
        }

        /// <summary>
        /// Retrieves the token type associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the token type associated with the specified token.
        /// </returns>
        public virtual Task<string> GetTokenTypeAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Task.FromResult(token.Type);
        }

        /// <summary>
        /// Executes the specified query.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<ImmutableArray<TToken>> ListAsync([CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            IQueryable<TToken> Query(IQueryable<TToken> tokens)
            {
                var query = tokens.OrderBy(token => token.Id).AsQueryable();

                if (offset.HasValue)
                {
                    query = query.Skip(offset.Value);
                }

                if (count.HasValue)
                {
                    query = query.Take(count.Value);
                }

                return query;
            }

            return ListAsync(Query, cancellationToken);
        }

        /// <summary>
        /// Executes the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public abstract Task<ImmutableArray<TResult>> ListAsync<TResult>([NotNull] Func<IQueryable<TToken>, IQueryable<TResult>> query, CancellationToken cancellationToken);

        /// <summary>
        /// Lists the tokens that are marked as expired or invalid
        /// and that can be safely removed from the database.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<ImmutableArray<TToken>> ListInvalidAsync([CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            IQueryable<TToken> Query(IQueryable<TToken> tokens)
            {
                var query = (from token in tokens
                             where token.ExpirationDate < DateTimeOffset.UtcNow ||
                                   token.Status != OpenIddictConstants.Statuses.Valid
                             orderby token.Id
                             select token).AsQueryable();

                if (offset.HasValue)
                {
                    query = query.Skip(offset.Value);
                }

                if (count.HasValue)
                {
                    query = query.Take(count.Value);
                }

                return query;
            }

            return ListAsync(Query, cancellationToken);
        }

        /// <summary>
        /// Sets the authorization identifier associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="identifier">The unique identifier associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public abstract Task SetAuthorizationIdAsync([NotNull] TToken token, [CanBeNull] string identifier, CancellationToken cancellationToken);

        /// <summary>
        /// Sets the application identifier associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="identifier">The unique identifier associated with the client application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public abstract Task SetApplicationIdAsync([NotNull] TToken token, [CanBeNull] string identifier, CancellationToken cancellationToken);

        /// <summary>
        /// Sets the expiration date associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="date">The date on which the token will no longer be considered valid.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetExpirationDateAsync([NotNull] TToken token,
            [CanBeNull] DateTimeOffset? date, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.ExpirationDate = date;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the status associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="status">The status associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetStatusAsync([NotNull] TToken token, [NotNull] string status, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.Status = status;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates an existing token.
        /// </summary>
        /// <param name="token">The token to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public abstract Task UpdateAsync([NotNull] TToken token, CancellationToken cancellationToken);

        /// <summary>
        /// Converts the provided identifier to a strongly typed key object.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided identifier.</returns>
        public virtual TKey ConvertIdentifierFromString([CanBeNull] string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return default(TKey);
            }

            return (TKey) TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(identifier);
        }

        /// <summary>
        /// Converts the provided identifier to its string representation.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>A <see cref="string"/> representation of the provided identifier.</returns>
        public virtual string ConvertIdentifierToString([CanBeNull] TKey identifier)
        {
            if (Equals(identifier, default(TKey)))
            {
                return null;
            }

            return TypeDescriptor.GetConverter(typeof(TKey)).ConvertToInvariantString(identifier);
        }
    }
}