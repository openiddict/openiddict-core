/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFramework.Models;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.EntityFramework
{
    /// <summary>
    /// Provides methods allowing to manage the scopes stored in a database.
    /// </summary>
    /// <typeparam name="TContext">The type of the Entity Framework database context.</typeparam>
    public class OpenIddictEntityFrameworkScopeStore<TContext> :
        OpenIddictEntityFrameworkScopeStore<OpenIddictEntityFrameworkScope, TContext, string>
        where TContext : DbContext
    {
        public OpenIddictEntityFrameworkScopeStore(
            IMemoryCache cache,
            TContext context,
            IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
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
    public class OpenIddictEntityFrameworkScopeStore<TScope, TContext, TKey> : IOpenIddictScopeStore<TScope>
        where TScope : OpenIddictEntityFrameworkScope<TKey>
        where TContext : DbContext
        where TKey : IEquatable<TKey>
    {
        public OpenIddictEntityFrameworkScopeStore(
            IMemoryCache cache,
            TContext context,
            IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
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
        protected IOptionsMonitor<OpenIddictEntityFrameworkOptions> Options { get; }

        /// <summary>
        /// Gets the database set corresponding to the <typeparamref name="TScope"/> entity.
        /// </summary>
        private DbSet<TScope> Scopes => Context.Set<TScope>();

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
            => await Scopes.LongCountAsync(cancellationToken);

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync<TResult>(Func<IQueryable<TScope>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Scopes).LongCountAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask CreateAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Scopes.Add(scope);

            await Context.SaveChangesAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask DeleteAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Scopes.Remove(scope);

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(scope).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID1244), exception);
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TScope?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1194), nameof(identifier));
            }

            var key = ConvertIdentifierFromString(identifier);

            return await (from scope in Scopes
                          where scope.Id!.Equals(key)
                          select scope).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TScope?> FindByNameAsync(string name, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1201), nameof(name));
            }

            return await (from scope in Scopes
                          where scope.Name == name
                          select scope).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TScope> FindByNamesAsync(
            ImmutableArray<string> names, CancellationToken cancellationToken)
        {
            if (names.Any(name => string.IsNullOrEmpty(name)))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1202), nameof(names));
            }

            // Note: Enumerable.Contains() is deliberately used without the extension method syntax to ensure
            // ImmutableArray.Contains() (which is not fully supported by Entity Framework 6.x) is not used instead.
            return (from scope in Scopes
                    where Enumerable.Contains(names, scope.Name)
                    select scope).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TScope> FindByResourceAsync(
            string resource, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID1061), nameof(resource));
            }

            // To optimize the efficiency of the query a bit, only scopes whose stringified
            // Resources column contains the specified resource are returned. Once the scopes
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this method in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var scopes = (from scope in Scopes
                              where scope.Resources!.Contains(resource)
                              select scope).AsAsyncEnumerable(cancellationToken);

                await foreach (var scope in scopes)
                {
                    var resources = await GetResourcesAsync(scope, cancellationToken);
                    if (resources.Contains(resource, StringComparer.Ordinal))
                    {
                        yield return scope;
                    }
                }
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TResult> GetAsync<TState, TResult>(
            Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Scopes, state).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetDescriptionAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(scope.Description);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (string.IsNullOrEmpty(scope.Descriptions))
            {
                return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());
            }

            // Note: parsing the stringified descriptions is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("42891062-8f69-43ba-9111-db7e8ded2553", "\x1e", scope.Descriptions);
            var descriptions = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<Dictionary<string, string>>(scope.Descriptions)
                    .ToImmutableDictionary(description => CultureInfo.GetCultureInfo(description.Key), description => description.Value);
            });

            return new ValueTask<ImmutableDictionary<CultureInfo, string>>(descriptions);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetDisplayNameAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(scope.DisplayName);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (string.IsNullOrEmpty(scope.DisplayNames))
            {
                return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());
            }

            // Note: parsing the stringified display names is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("e17d437b-bdd2-43f3-974e-46d524f4bae1", "\x1e", scope.DisplayNames);
            var names = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<Dictionary<string, string>>(scope.DisplayNames)
                    .ToImmutableDictionary(name => CultureInfo.GetCultureInfo(name.Key), name => name.Value);
            });

            return new ValueTask<ImmutableDictionary<CultureInfo, string>>(names);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetIdAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(ConvertIdentifierToString(scope.Id));
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetNameAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(scope.Name);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (string.IsNullOrEmpty(scope.Properties))
            {
                return new ValueTask<ImmutableDictionary<string, JsonElement>>(ImmutableDictionary.Create<string, JsonElement>());
            }

            // Note: parsing the stringified properties is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("78d8dfdd-3870-442e-b62e-dc9bf6eaeff7", "\x1e", scope.Properties);
            var properties = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                return JsonSerializer.Deserialize<ImmutableDictionary<string, JsonElement>>(scope.Properties);
            });

            return new ValueTask<ImmutableDictionary<string, JsonElement>>(properties);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetResourcesAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
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

                return JsonSerializer.Deserialize<ImmutableArray<string>>(scope.Resources);
            });

            return new ValueTask<ImmutableArray<string>>(resources);
        }

        /// <inheritdoc/>
        public virtual ValueTask<TScope> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TScope>(Activator.CreateInstance<TScope>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TScope>(Task.FromException<TScope>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID1245), exception)));
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TScope> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            var query = Scopes.OrderBy(scope => scope.Id!).AsQueryable();

            if (offset.HasValue)
            {
                query = query.Skip(offset.Value);
            }

            if (count.HasValue)
            {
                query = query.Take(count.Value);
            }

            return query.AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
            Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(Scopes, state).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDescriptionAsync(TScope scope, string? description, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.Description = description;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDescriptionsAsync(TScope scope,
            ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (descriptions is null || descriptions.IsEmpty)
            {
                scope.Descriptions = null;

                return default;
            }

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            });

            writer.WriteStartObject();

            foreach (var description in descriptions)
            {
                writer.WritePropertyName(description.Key.Name);
                writer.WriteStringValue(description.Value);
            }

            writer.WriteEndObject();
            writer.Flush();

            scope.Descriptions = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNameAsync(TScope scope, string? name, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.DisplayName = name;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNamesAsync(TScope scope,
            ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (names is null || names.IsEmpty)
            {
                scope.DisplayNames = null;

                return default;
            }

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            });

            writer.WriteStartObject();

            foreach (var name in names)
            {
                writer.WritePropertyName(name.Key.Name);
                writer.WriteStringValue(name.Value);
            }

            writer.WriteEndObject();
            writer.Flush();

            scope.DisplayNames = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetNameAsync(TScope scope, string? name, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.Name = name;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPropertiesAsync(TScope scope,
            ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (properties is null || properties.IsEmpty)
            {
                scope.Properties = null;

                return default;
            }

            scope.Properties = JsonSerializer.Serialize(properties, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            });

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetResourcesAsync(TScope scope, ImmutableArray<string> resources, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (resources.IsDefaultOrEmpty)
            {
                scope.Resources = null;

                return default;
            }

            scope.Resources = JsonSerializer.Serialize(resources, new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                WriteIndented = false
            });

            return default;
        }

        /// <inheritdoc/>
        public virtual async ValueTask UpdateAsync(TScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Scopes.Attach(scope);

            // Generate a new concurrency token and attach it
            // to the scope before persisting the changes.
            scope.ConcurrencyToken = Guid.NewGuid().ToString();

            Context.Entry(scope).State = EntityState.Modified;

            try
            {
                await Context.SaveChangesAsync(cancellationToken);
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Entry(scope).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID1244), exception);
            }
        }

        /// <summary>
        /// Converts the provided identifier to a strongly typed key object.
        /// </summary>
        /// <param name="identifier">The identifier to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided identifier.</returns>
        public virtual TKey? ConvertIdentifierFromString(string? identifier)
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
        public virtual string? ConvertIdentifierToString(TKey? identifier)
        {
            if (Equals(identifier, default(TKey)))
            {
                return null;
            }

            return TypeDescriptor.GetConverter(typeof(TKey)).ConvertToInvariantString(identifier);
        }
    }
}