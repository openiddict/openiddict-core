/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Core;
using OpenIddict.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    public class OpenIddictScopeStore<TContext> : OpenIddictScopeStore<OpenIddictScope, TContext, string>
        where TContext : DbContext
    {
        public OpenIddictScopeStore([NotNull] TContext context) : base(context) { }
    }

    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictScopeStore<TContext, TKey> : OpenIddictScopeStore<OpenIddictScope<TKey>, TContext, TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictScopeStore([NotNull] TContext context) : base(context) { }
    }

    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictScopeStore<TScope, TContext, TKey> : IOpenIddictScopeStore<TScope>
        where TScope : OpenIddictScope<TKey>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictScopeStore([NotNull] TContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Context = context;
        }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        protected virtual TContext Context { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TScope"/> entity.
        /// </summary>
        protected DbSet<TScope> Scopes => Context.Set<TScope>();

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

            return (TKey) TypeDescriptor.GetConverter(typeof(TKey))
                                        .ConvertFromInvariantString(identifier);
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

            return TypeDescriptor.GetConverter(typeof(TKey))
                                 .ConvertToInvariantString(identifier);
        }
    }
}