/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace OpenIddict {
    /// <summary>
    /// Creates a new instance of a persistence store for the specified user type.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TApplication">The type representing an application.</typeparam>
    /// <typeparam name="TAuthorization">The type representing an authorization.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TToken">The type representing a token.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">
    /// The type of the primary key for a user, an application, an authorization, a role and a token.
    /// </typeparam>
    public class OpenIddictUserStore<TUser, TApplication, TAuthorization, TRole, TToken, TContext, TKey> :
        UserStore<TUser, TRole, TContext, TKey>, IOpenIddictUserStore<TUser>
        where TUser : OpenIddictUser<TKey, TAuthorization, TToken>, new()
        where TApplication : OpenIddictApplication<TKey, TToken>
        where TAuthorization : OpenIddictAuthorization<TKey, TToken>
        where TRole : IdentityRole<TKey>
        where TToken : OpenIddictToken<TKey>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey> {
        public OpenIddictUserStore(TContext context)
            : base(context) { }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TApplication"/> entity.
        /// </summary>
        protected DbSet<TApplication> Applications => Context.Set<TApplication>();

        /// <summary>
        /// Creates a new token associated with the given user.
        /// </summary>
        /// <param name="user">The user associated with the token.</param>
        /// <param name="type">The token type.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        /// <exception cref="System.ArgumentException">The token type cannot be null or empty.</exception>
        /// <exception cref="System.InvalidOperationException"></exception> // TODO: Add reason
        public virtual async Task<string> CreateTokenAsync(TUser user, string type, CancellationToken cancellationToken) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentException("The token type cannot be null or empty.");
            }

            // Ensure that the key type can be serialized.
            var converter = TypeDescriptor.GetConverter(typeof(TKey));
            if (!converter.CanConvertTo(typeof(string))) {
                throw new InvalidOperationException($"The '{typeof(TKey).Name}' key type is not supported.");
            }

            var token = new TToken { Type = type };
            user.Tokens.Add(token);

            Context.Update(user);

            await Context.SaveChangesAsync(cancellationToken);

            return converter.ConvertToInvariantString(token.Id);
        }

        /// <summary>
        /// Creates a new token associated with the given user and
        /// attached to the tokens issued to the specified client.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="client">The application.</param>
        /// <param name="type">The token type.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        /// <exception cref="System.ArgumentException">
        /// The client identifier cannot be null or empty.
        /// or
        /// The token type cannot be null or empty.
        /// </exception>
        /// <exception cref="System.InvalidOperationException">
        /// The application cannot be found in the database.
        /// </exception>
        public virtual async Task<string> CreateTokenAsync(TUser user, string client, string type, CancellationToken cancellationToken) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrEmpty(client)) {
                throw new ArgumentException("The client identifier cannot be null or empty.");
            }

            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentException("The token type cannot be null or empty.");
            }

            // Ensure that the key type can be serialized.
            var converter = TypeDescriptor.GetConverter(typeof(TKey));
            if (!converter.CanConvertTo(typeof(string))) {
                throw new InvalidOperationException($"The '{typeof(TKey).Name}' key type is not supported.");
            }

            var application = await Applications.FirstOrDefaultAsync(entity => entity.ClientId.Equals(client), cancellationToken);
            if (application == null) {
                throw new InvalidOperationException("The application cannot be found in the database.");
            }

            var token = new TToken { Type = type };

            application.Tokens.Add(token);
            user.Tokens.Add(token);

            Context.Update(application);
            Context.Update(user);

            await Context.SaveChangesAsync(cancellationToken);

            return converter.ConvertToInvariantString(token.Id);
        }

        /// <summary>
        /// Retrieves the token identifiers associated with a user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="T:System.Threading.Tasks.Task" /> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the user.
        /// </returns>
        /// <exception cref="System.ArgumentNullException"></exception> // TODO: Add reason
        /// <exception cref="System.InvalidOperationException"></exception> // TODO: Add reason
        public virtual async Task<IEnumerable<string>> GetTokensAsync(TUser user, CancellationToken cancellationToken) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            // Ensure that the key type can be serialized.
            var converter = TypeDescriptor.GetConverter(typeof(TKey));
            if (!converter.CanConvertTo(typeof(string))) {
                throw new InvalidOperationException($"The '{typeof(TKey).Name}' key type is not supported.");
            }

            var query = from entity in Users
                        where entity.Id.Equals(user.Id)
                        from token in entity.Tokens
                        select token.Id;

            var tokens = new List<string>();

            foreach (var identifier in await query.ToArrayAsync()) {
                tokens.Add(converter.ConvertToInvariantString(identifier));
            }

            return tokens;
        }
    }
}