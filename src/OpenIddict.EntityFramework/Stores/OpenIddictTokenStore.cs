/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace OpenIddict {
    /// <summary>
    /// Provides methods allowing to manage the tokens stored in a database.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictTokenStore<TToken, TContext, TKey> : IOpenIddictTokenStore<TToken>
        where TToken : OpenIddictToken<TKey>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey> {
        public OpenIddictTokenStore(TContext context) {
            Context = context;
        }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        protected virtual TContext Context { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TToken"/> entity.
        /// </summary>
        protected DbSet<TToken> Tokens => Context.Set<TToken>();

        /// <summary>
        /// Creates a new token, defined by a unique identifier and a token type.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the token to create.</param>
        /// <param name="type">The token type.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task CreateAsync(string identifier, string type, CancellationToken cancellationToken) {
            var converter = TypeDescriptor.GetConverter(typeof(TKey));

            // Ensure that the key type is compatible with string keys.
            if (!converter.CanConvertFrom(typeof(string))) {
                return Task.FromResult(0);
            }

            var key = (TKey) converter.ConvertFromInvariantString(identifier);

            var token = new TToken { Id = key, Type = type };
            Tokens.Add(token);

            return Context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Retrieves an token using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the token.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task<TToken> FindByIdAsync(string identifier, CancellationToken cancellationToken) {
            var converter = TypeDescriptor.GetConverter(typeof(TKey));

            // If the string key cannot be converted to TKey, return null
            // to indicate that the requested token doesn't exist.
            if (!converter.CanConvertFrom(typeof(string))) {
                return Task.FromResult<TToken>(null);
            }

            var key = (TKey) converter.ConvertFromInvariantString(identifier);

            return Tokens.SingleOrDefaultAsync(token => token.Id.Equals(key), cancellationToken);
        }

        /// <summary>
        /// Revokes a token.
        /// </summary>
        /// <param name="token">The token to revoke.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task RevokeAsync(TToken token, CancellationToken cancellationToken) {
            if (token == null) {
                throw new ArgumentNullException(nameof(token));
            }

            Context.Remove(token);

            return Context.SaveChangesAsync(cancellationToken);
        }
    }
}