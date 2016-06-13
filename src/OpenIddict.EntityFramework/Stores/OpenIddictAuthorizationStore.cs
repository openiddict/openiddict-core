/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.EntityFrameworkCore;

namespace OpenIddict {
    /// <summary>
    /// Represents a new instance of a persistence store for the specified authorization and token types.
    /// </summary>
    /// <typeparam name="TAuthorization">The type representing an authorization.</typeparam>
    /// <typeparam name="TToken">The type representing a token.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for an authorization and a token.</typeparam>
    public class OpenIddictAuthorizationStore<TAuthorization, TToken, TContext, TKey> : IOpenIddictAuthorizationStore<TAuthorization>
        where TAuthorization : OpenIddictAuthorization<TKey, TToken>
        where TToken : OpenIddictToken<TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey> {
        public OpenIddictAuthorizationStore(TContext context) {
            Context = context;
        }

        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        protected virtual TContext Context { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TAuthorization"/> entity.
        /// </summary>
        protected DbSet<TAuthorization> Authorizations => Context.Set<TAuthorization>();
    }
}