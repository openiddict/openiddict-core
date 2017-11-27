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
    /// Provides methods allowing to manage the scopes stored in a database.
    /// Note: this base class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public abstract class OpenIddictScopeStore<TScope, TKey> : IOpenIddictScopeStore<TScope>
        where TScope : OpenIddictScope<TKey>, new()
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Determines the number of scopes that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of scopes in the database.
        /// </returns>
        public virtual Task<long> CountAsync(CancellationToken cancellationToken)
        {
            return CountAsync(scopes => scopes, cancellationToken);
        }

        /// <summary>
        /// Determines the number of scopes that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of scopes that match the specified query.
        /// </returns>
        public abstract Task<long> CountAsync<TResult>([NotNull] Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken);

        /// <summary>
        /// Creates a new scope.
        /// </summary>
        /// <param name="scope">The scope to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result returns the scope.
        /// </returns>
        public abstract Task<TScope> CreateAsync([NotNull] TScope scope, CancellationToken cancellationToken);

        /// <summary>
        /// Removes an existing scope.
        /// </summary>
        /// <param name="scope">The scope to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public abstract Task DeleteAsync([NotNull] TScope scope, CancellationToken cancellationToken);

        /// <summary>
        /// Executes the specified query and returns the first element.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the first element returned when executing the query.
        /// </returns>
        public abstract Task<TResult> GetAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the description associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the description associated with the specified scope.
        /// </returns>
        public virtual Task<string> GetDescriptionAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return Task.FromResult(scope.Description);
        }

        /// <summary>
        /// Retrieves the name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the name associated with the specified scope.
        /// </returns>
        public virtual Task<string> GetNameAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return Task.FromResult(scope.Name);
        }

        /// <summary>
        /// Instantiates a new scope.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the instantiated scope, that can be persisted in the database.
        /// </returns>
        public virtual Task<TScope> InstantiateAsync(CancellationToken cancellationToken) => Task.FromResult(new TScope());

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <param name="count">The number of results to return.</param>
        /// <param name="offset">The number of results to skip.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public virtual Task<ImmutableArray<TScope>> ListAsync([CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            IQueryable<TScope> Query(IQueryable<TScope> scopes, int? skip, int? take)
            {
                var query = scopes.OrderBy(scope => scope.Id).AsQueryable();

                if (skip.HasValue)
                {
                    query = query.Skip(skip.Value);
                }

                if (take.HasValue)
                {
                    query = query.Take(take.Value);
                }

                return query;
            }

            return ListAsync((scopes, state) => Query(scopes, state.offset, state.count), (offset, count), cancellationToken);
        }

        /// <summary>
        /// Executes the specified query and returns all the corresponding elements.
        /// </summary>
        /// <typeparam name="TState">The state type.</typeparam>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="state">The optional state.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the elements returned when executing the specified query.
        /// </returns>
        public abstract Task<ImmutableArray<TResult>> ListAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken);

        /// <summary>
        /// Sets the description associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="description">The description associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetDescriptionAsync([NotNull] TScope scope, [CanBeNull] string description, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.Description = description;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="name">The name associated with the authorization.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetNameAsync([NotNull] TScope scope, [CanBeNull] string name, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.Name = name;

            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates an existing scope.
        /// </summary>
        /// <param name="scope">The scope to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public abstract Task UpdateAsync([NotNull] TScope scope, CancellationToken cancellationToken);

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