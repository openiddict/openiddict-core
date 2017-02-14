/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to manage the tokens stored in the store.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    public class OpenIddictTokenManager<TToken> where TToken : class
    {
        public OpenIddictTokenManager(
            [NotNull] IOpenIddictTokenStore<TToken> store,
            [NotNull] ILogger<OpenIddictTokenManager<TToken>> logger)
        {
            Logger = logger;
            Store = store;
        }

        /// <summary>
        /// Gets the logger associated with the current manager.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected IOpenIddictTokenStore<TToken> Store { get; }

        /// <summary>
        /// Creates a new token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the token.
        /// </returns>
        public virtual async Task<TToken> CreateAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            await ValidateAsync(token, cancellationToken);
            return await Store.CreateAsync(token, cancellationToken);
        }

        /// <summary>
        /// Creates a new token, which is associated with a particular subject.
        /// </summary>
        /// <param name="type">The token type.</param>
        /// <param name="subject">The subject associated with the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the token.
        /// </returns>
        public virtual async Task<TToken> CreateAsync([NotNull] string type, [NotNull] string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The token type cannot be null or empty.", nameof(type));
            }

            if (!string.Equals(type, OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, OpenIdConnectConstants.TokenTypeHints.RefreshToken, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("The specified token type is not supported by the default token manager.");
            }

            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException("The subject cannot be null or empty.");
            }

            return await Store.CreateAsync(type, subject, cancellationToken);
        }

        /// <summary>
        /// Retrieves a token using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the token corresponding to the unique identifier.
        /// </returns>
        public virtual Task<TToken> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            return Store.FindByIdAsync(identifier, cancellationToken);
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
        public virtual Task<TToken[]> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
        {
            return Store.FindBySubjectAsync(subject, cancellationToken);
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

            return Store.GetIdAsync(token, cancellationToken);
        }

        /// <summary>
        /// Revokes a token.
        /// </summary>
        /// <param name="token">The token to revoke.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task RevokeAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Store.RevokeAsync(token, cancellationToken);
        }

        /// <summary>
        /// Sets the authorization associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="identifier">The unique identifier associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task SetAuthorizationAsync([NotNull] TToken token, [CanBeNull] string identifier, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            await Store.SetAuthorizationAsync(token, identifier, cancellationToken);
            await UpdateAsync(token, cancellationToken);
        }

        /// <summary>
        /// Sets the client application associated with a token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="identifier">The unique identifier associated with the client application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task SetClientAsync([NotNull] TToken token, [CanBeNull] string identifier, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            await Store.SetClientAsync(token, identifier, cancellationToken);
            await UpdateAsync(token, cancellationToken);
        }

        /// <summary>
        /// Updates an existing token.
        /// </summary>
        /// <param name="token">The token to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task UpdateAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return Store.UpdateAsync(token, cancellationToken);
        }

        /// <summary>
        /// Validates the token to ensure it's in a consistent state.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        protected virtual async Task ValidateAsync([NotNull] TToken token, CancellationToken cancellationToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            var type = await Store.GetTokenTypeAsync(token, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The token type cannot be null or empty.", nameof(token));
            }

            if (!string.Equals(type, OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, OpenIdConnectConstants.TokenTypeHints.RefreshToken, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("The specified token type is not supported by the default token manager.");
            }

            if (string.IsNullOrEmpty(await Store.GetSubjectAsync(token, cancellationToken)))
            {
                throw new ArgumentException("The subject cannot be null or empty.");
            }
        }
    }
}