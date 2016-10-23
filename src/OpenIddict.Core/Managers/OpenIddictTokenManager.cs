/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict {
    /// <summary>
    /// Provides methods allowing to manage the tokens stored in the store.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    public class OpenIddictTokenManager<TToken> where TToken : class {
        public OpenIddictTokenManager(
            [NotNull] IServiceProvider services,
            [NotNull] IOpenIddictTokenStore<TToken> store,
            [NotNull] ILogger<OpenIddictTokenManager<TToken>> logger) {
            Context = services?.GetService<IHttpContextAccessor>()?.HttpContext;
            Logger = logger;
            Store = store;
        }

        /// <summary>
        /// Gets the cancellation token used to abort async operations.
        /// </summary>
        protected CancellationToken CancellationToken => Context?.RequestAborted ?? CancellationToken.None;

        /// <summary>
        /// Gets the HTTP context associated with the current manager.
        /// </summary>
        protected HttpContext Context { get; }

        /// <summary>
        /// Gets the logger associated with the current manager.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected IOpenIddictTokenStore<TToken> Store { get; }

        /// <summary>
        /// Creates a new token, which is not associated with a particular user or client.
        /// </summary>
        /// <param name="type">The token type.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        public virtual Task<string> CreateAsync(string type) {
            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentException("The token type cannot be null or empty.", nameof(type));
            }

            return Store.CreateAsync(type, CancellationToken);
        }

        /// <summary>
        /// Retrieves a token using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the token.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the token corresponding to the unique identifier.
        /// </returns>
        public virtual Task<TToken> FindByIdAsync(string identifier) {
            return Store.FindByIdAsync(identifier, CancellationToken);
        }

        /// <summary>
        /// Revokes a token.
        /// </summary>
        /// <param name="token">The token to revoke.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task RevokeAsync(TToken token) {
            if (token == null) {
                throw new ArgumentNullException(nameof(token));
            }

            return Store.RevokeAsync(token, CancellationToken);
        }
    }
}