/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;

namespace OpenIddict.EntityFrameworkCore
{
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    public class OpenIddictScopeStore<TContext> : OpenIddictScopeStore<OpenIddictScope, TContext, string>
        where TContext : DbContext
    {
        public OpenIddictScopeStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
            : base(cache, context, options)
        {
        }
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
        public OpenIddictScopeStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
            : base(cache, context, options)
        {
        }
    }

    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// </summary>
    /// <typeparam name="TScope">The type of the Scope entity.</typeparam>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    /// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
    public class OpenIddictScopeStore<TScope, TContext, TKey> : IOpenIddictScopeStore<TScope>
        where TScope : OpenIddictScope<TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictScopeStore(
            [NotNull] IMemoryCache cache,
            [NotNull] TContext context,
            [NotNull] IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        {
            Cache = cache;
            Context = context;
            Options = options;
        }

        /// <summary>
        /// Gets the memory cache associated with the current store.
        /// </summary>
        protected IMemoryCache Cache { get; }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        protected TContext Context { get; }

        /// <summary>
        /// Gets the options associated with the current store.
        /// </summary>
        protected IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> Options { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TScope"/> entity.
        /// </summary>
        private DbSet<TScope> Scopes => Context.Set<TScope>();

        /// <summary>
        /// Determines the number of scopes that exist in the database.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the number of scopes in the database.
        /// </returns>
        public virtual Task<long> CountAsync(CancellationToken cancellationToken)
            => Scopes.LongCountAsync();

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
        public virtual Task<long> CountAsync<TResult>([NotNull] Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken)
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
        public virtual Task CreateAsync([NotNull] TScope scope, CancellationToken cancellationToken)
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
        public virtual async Task DeleteAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Context.Remove(scope);

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException exception)
            {
                throw new OpenIddictExceptions.ConcurrencyException(new StringBuilder()
                    .AppendLine("The scope was concurrently updated and cannot be persisted in its current state.")
                    .Append("Reload the scope from the database and retry the operation.")
                    .ToString(), exception);
            }
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve a scope using its unique identifier.
        /// </summary>
        private static readonly Func<TContext, TKey, Task<TScope>> FindById =
            EF.CompileAsyncQuery((TContext context, TKey identifier) =>
                (from scope in context.Set<TScope>().AsTracking()
                 where scope.Id.Equals(identifier)
                 select scope).FirstOrDefault());

        /// <summary>
        /// Retrieves a scope using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the identifier.
        /// </returns>
        public virtual Task<TScope> FindByIdAsync([NotNull] string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            return FindById(Context, ConvertIdentifierFromString(identifier));
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve a scope using its name.
        /// </summary>
        private static readonly Func<TContext, string, Task<TScope>> FindByName =
            EF.CompileAsyncQuery((TContext context, string name) =>
                (from scope in context.Set<TScope>().AsTracking()
                 where scope.Name == name
                 select scope).FirstOrDefault());

        /// <summary>
        /// Retrieves a scope using its name.
        /// </summary>
        /// <param name="name">The name associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scope corresponding to the specified name.
        /// </returns>
        public virtual Task<TScope> FindByNameAsync([NotNull] string name, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The scope name cannot be null or empty.", nameof(name));
            }

            return FindByName(Context, name);
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve a list of scopes using their name.
        /// </summary>
        private static readonly Func<TContext, ImmutableArray<string>, IAsyncEnumerable<TScope>> FindByNames =
            EF.CompileAsyncQuery((TContext context, ImmutableArray<string> names) =>
                from scope in context.Set<TScope>().AsTracking()
                where names.Contains(scope.Name)
                select scope);

        /// <summary>
        /// Retrieves a list of scopes using their name.
        /// </summary>
        /// <param name="names">The names associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes corresponding to the specified names.
        /// </returns>
        public virtual async Task<ImmutableArray<TScope>> FindByNamesAsync(
            ImmutableArray<string> names, CancellationToken cancellationToken)
        {
            if (names.Any(name => string.IsNullOrEmpty(name)))
            {
                throw new ArgumentException("Scope names cannot be null or empty.", nameof(names));
            }

            var builder = ImmutableArray.CreateBuilder<TScope>();

            await foreach (var scope in FindByNames(Context, names))
            {
                builder.Add(scope);
            }

            return builder.ToImmutable();
        }

        /// <summary>
        /// Exposes a compiled query allowing to retrieve all the scopes that contain the specified resource.
        /// </summary>
        private static readonly Func<TContext, string, IAsyncEnumerable<TScope>> FindByResource =
            // To optimize the efficiency of the query a bit, only scopes whose stringified
            // Resources column contains the specified resource are returned. Once the scopes
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this query in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.
            EF.CompileAsyncQuery((TContext context, string resource) =>
                from scope in context.Set<TScope>().AsTracking()
                where scope.Resources.Contains(resource)
                select scope);

        /// <summary>
        /// Retrieves all the scopes that contain the specified resource.
        /// </summary>
        /// <param name="resource">The resource associated with the scopes.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the scopes associated with the specified resource.
        /// </returns>
        public virtual async Task<ImmutableArray<TScope>> FindByResourceAsync(
            [NotNull] string resource, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException("The resource cannot be null or empty.", nameof(resource));
            }

            var builder = ImmutableArray.CreateBuilder<TScope>();

            await foreach (var scope in FindByResource(Context, resource))
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
        public virtual Task<TResult> GetAsync<TState, TResult>(
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
        /// Retrieves the description associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the description associated with the specified scope.
        /// </returns>
        public virtual ValueTask<string> GetDescriptionAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string>(scope.Description);
        }

        /// <summary>
        /// Retrieves the display name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the scope.
        /// </returns>
        public virtual ValueTask<string> GetDisplayNameAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string>(scope.DisplayName);
        }

        /// <summary>
        /// Retrieves the unique identifier associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the scope.
        /// </returns>
        public virtual ValueTask<string> GetIdAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string>(ConvertIdentifierToString(scope.Id));
        }

        /// <summary>
        /// Retrieves the name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the name associated with the specified scope.
        /// </returns>
        public virtual ValueTask<string> GetNameAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string>(scope.Name);
        }

        /// <summary>
        /// Retrieves the additional properties associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the additional properties associated with the scope.
        /// </returns>
        public virtual ValueTask<JObject> GetPropertiesAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (string.IsNullOrEmpty(scope.Properties))
            {
                return new ValueTask<JObject>(new JObject());
            }

            // Note: parsing the stringified properties is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("78d8dfdd-3870-442e-b62e-dc9bf6eaeff7", "\x1e", scope.Properties);
            var properties = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JObject.Parse(scope.Properties);
            });

            return new ValueTask<JObject>((JObject) properties.DeepClone());
        }

        /// <summary>
        /// Retrieves the resources associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns all the resources associated with the scope.
        /// </returns>
        public virtual ValueTask<ImmutableArray<string>> GetResourcesAsync([NotNull] TScope scope, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (string.IsNullOrEmpty(scope.Resources))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            // Note: parsing the stringified resources is an expensive operation.
            // To mitigate that, the resulting array is stored in the memory cache.
            var key = string.Concat("b6148250-aede-4fb9-a621-07c9bcf238c3", "\x1e", scope.Resources);
            var resources = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JArray.Parse(scope.Resources)
                    .Select(element => (string) element)
                    .ToImmutableArray();
            });

            return new ValueTask<ImmutableArray<string>>(resources);
        }

        /// <summary>
        /// Instantiates a new scope.
        /// </summary>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the instantiated scope, that can be persisted in the database.
        /// </returns>
        public virtual ValueTask<TScope> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TScope>(Activator.CreateInstance<TScope>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TScope>(Task.FromException<TScope>(
                    new InvalidOperationException(new StringBuilder()
                        .AppendLine("An error occurred while trying to create a new scope instance.")
                        .Append("Make sure that the scope entity is not abstract and has a public parameterless constructor ")
                        .Append("or create a custom scope store that overrides 'InstantiateAsync()' to use a custom factory.")
                        .ToString(), exception)));
            }
        }

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
        public virtual async Task<ImmutableArray<TScope>> ListAsync(
            [CanBeNull] int? count, [CanBeNull] int? offset, CancellationToken cancellationToken)
        {
            var query = Scopes.OrderBy(scope => scope.Id).AsTracking();

            if (offset.HasValue)
            {
                query = query.Skip(offset.Value);
            }

            if (count.HasValue)
            {
                query = query.Take(count.Value);
            }

            return ImmutableArray.CreateRange(await query.ToListAsync(cancellationToken));
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
        public virtual async Task<ImmutableArray<TResult>> ListAsync<TState, TResult>(
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
        /// Sets the display name associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="name">The display name associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetDisplayNameAsync([NotNull] TScope scope, [CanBeNull] string name, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.DisplayName = name;

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
        /// Sets the additional properties associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="properties">The additional properties associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetPropertiesAsync([NotNull] TScope scope, [CanBeNull] JObject properties, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (properties == null)
            {
                scope.Properties = null;

                return Task.CompletedTask;
            }

            scope.Properties = properties.ToString(Formatting.None);

            return Task.CompletedTask;
        }

        /// <summary>
        /// Sets the resources associated with a scope.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="resources">The resources associated with the scope.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task SetResourcesAsync([NotNull] TScope scope, ImmutableArray<string> resources, CancellationToken cancellationToken)
        {
            if (scope == null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (resources.IsDefaultOrEmpty)
            {
                scope.Resources = null;

                return Task.CompletedTask;
            }

            scope.Resources = new JArray(resources.ToArray()).ToString(Formatting.None);

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
        public virtual async Task UpdateAsync([NotNull] TScope scope, CancellationToken cancellationToken)
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

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException exception)
            {
                throw new OpenIddictExceptions.ConcurrencyException(new StringBuilder()
                    .AppendLine("The scope was concurrently updated and cannot be persisted in its current state.")
                    .Append("Reload the scope from the database and retry the operation.")
                    .ToString(), exception);
            }
        }

        /// <summary>
        /// Converts the provided identifier to a strongly typed key object.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided identifier.</returns>
        public virtual TKey ConvertIdentifierFromString([CanBeNull] string identifier)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                return default;
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