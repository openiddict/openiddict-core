/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OpenIddict.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// Note: this class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    public class OpenIddictScopeStore<TContext> : OpenIddictScopeStore<OpenIddictScope, TContext, string>
        where TContext : DbContext
    {
        public OpenIddictScopeStore([NotNull] TContext context, [NotNull] IMemoryCache cache)
            : base(context, cache)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// Note: this class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictScopeStore<TContext, TKey> : OpenIddictScopeStore<OpenIddictScope<TKey>, TContext, TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictScopeStore([NotNull] TContext context, [NotNull] IMemoryCache cache)
            : base(context, cache)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// Note: this class can only be used with the default OpenIddict entities.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictScopeStore<TScope, TContext, TKey> : Stores.OpenIddictScopeStore<TScope, TKey>
        where TScope : OpenIddictScope<TKey>, new()
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictScopeStore([NotNull] TContext context, [NotNull] IMemoryCache cache)
            : base(cache)
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
        /// Determines the number of scopes that match the specified query.
        /// </summary>
        /// <typeparam name="TResult">The result type.</typeparam>
        /// <param name="query">The query to execute.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of scopes that match the specified query.
        /// </returns>
        public override Task<long> CountAsync<TResult>([NotNull] Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(Scopes).LongCountAsync();
        }

        /// <summary>
        /// Creates a new scope.
        /// </summary>
        /// <param name="scope">The scope to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public override Task CreateAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Scopes.Add(scope);

            return Context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Removes an existing scope.
        /// </summary>
        /// <param name="scope">The scope to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public override Task DeleteAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Context.Remove(scope);

            return Context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Retrieves a scope using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the identifier.
        /// </returns>
        public override Task<TScope> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var query = Cache.GetOrCreate("485f3372-2d38-4418-8d1e-acd8aa0c3555", entry =>
            {
                entry.SetPriority(CacheItemPriority.NeverRemove);

                return EF.CompileAsyncQuery((TContext context, TKey key) =>
                    (from scope in context.Set<TScope>().AsTracking()
                     where scope.Id.Equals(key)
                     select scope).FirstOrDefault());
            });

            return query(Context, ConvertIdentifierFromString(identifier));
        }

        /// <summary>
        /// Retrieves a scope using its name.
        /// </summary>
        /// <param name="name">The name associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the specified name.
        /// </returns>
        public override Task<TScope> FindByNameAsync([NotNull] string name, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The scope name cannot be null or empty.", nameof(name));
            }

            var query = Cache.GetOrCreate("71cb2f7a-7adb-4b3e-8833-772e254f9b03", entry =>
            {
                entry.SetPriority(CacheItemPriority.NeverRemove);

                return EF.CompileAsyncQuery((TContext context, string id) =>
                    (from scope in context.Set<TScope>().AsTracking()
                     where scope.Name == id
                     select scope).FirstOrDefault());
            });

            return query(Context, name);
        }

        /// <summary>
        /// Retrieves a list of scopes using their name.
        /// </summary>
        /// <param name="names">The names associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes corresponding to the specified names.
        /// </returns>
        public override async Task<ImmutableArray<TScope>> FindByNamesAsync(
            ImmutableArray<string> names, CancellationToken cancellationToken)
        {
            if (names.Any(name => string.IsNullOrEmpty(name)))
            {
                throw new ArgumentException("Scope names cannot be null or empty.", nameof(names));
            }

            var query = Cache.GetOrCreate("e19404af-8586-4693-9b9c-8185b653ee2d", entry =>
            {
                entry.SetPriority(CacheItemPriority.NeverRemove);

                return EF.CompileAsyncQuery((TContext context, ImmutableArray<string> ids) =>
                    from scope in context.Set<TScope>().AsTracking()
                    where ids.Contains(scope.Name)
                    select scope);
            });

            return ImmutableArray.CreateRange(await query(Context, names).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Retrieves all the scopes that contain the specified resource.
        /// </summary>
        /// <param name="resource">The resource associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes associated with the specified resource.
        /// </returns>
        public override async Task<ImmutableArray<TScope>> FindByResourceAsync(
            [NotNull] string resource, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException("The resource cannot be null or empty.", nameof(resource));
            }

            // To optimize the efficiency of the query a bit, only scopes whose stringified
            // Resources column contains the specified resource are returned. Once the scopes
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this method in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.
            var query = Cache.GetOrCreate("45bae754-72fc-422c-b3a2-90867600a029", entry =>
            {
                entry.SetPriority(CacheItemPriority.NeverRemove);

                return EF.CompileAsyncQuery((TContext context, string value) =>
                    from scope in context.Set<TScope>().AsTracking()
                    where scope.Resources.Contains(value)
                    select scope);
            });

            var builder = ImmutableArray.CreateBuilder<TScope>();

            foreach (var scope in await query(Context, resource).ToListAsync(cancellationToken))
            {
                var resources = await GetResourcesAsync(scope, cancellationToken);
                if (resources.Contains(resource, StringComparer.Ordinal))
                {
                    builder.Add(scope);
                }
            }

            return builder.ToImmutable();
        }

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
        public override Task<TResult> GetAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(Scopes.AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
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
        public override async Task<ImmutableArray<TResult>> ListAsync<TState, TResult>(
            [NotNull] Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            [CanBeNull] TState state, CancellationToken cancellationToken)
        {
            if (query == null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return ImmutableArray.CreateRange(await query(Scopes.AsTracking(), state).ToListAsync(cancellationToken));
        }

        /// <summary>
        /// Updates an existing scope.
        /// </summary>
        /// <param name="scope">The scope to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public override Task UpdateAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Context.Attach(scope);

            // Generate a new concurrency token and attach it
            // to the scope before persisting the changes.
            scope.ConcurrencyToken = Guid.NewGuid().ToString();

            Context.Update(scope);

            return Context.SaveChangesAsync(cancellationToken);
        }
    }
}