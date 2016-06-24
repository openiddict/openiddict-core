/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.EntityFrameworkCore;

namespace OpenIddict {
    /// <summary>
    /// Creates a new instance of a persistence store for the specified authorization scope type.
    /// </summary>
    /// <typeparam name="TScope">The type representing a scope.</typeparam>
    /// <typeparam name="TContext">The type of the data context class used to access the store.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a scope.</typeparam>
    public class OpenIddictScopeStore<TScope, TContext, TKey> : IOpenIddictScopeStore<TScope>
        where TScope : OpenIddictScope<TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey> {
        public OpenIddictScopeStore(TContext context) {
            Context = context;
        }

        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        protected virtual TContext Context { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TScope"/> entity.
        /// </summary>
        protected DbSet<TScope> Authorizations => Context.Set<TScope>();
    }
}