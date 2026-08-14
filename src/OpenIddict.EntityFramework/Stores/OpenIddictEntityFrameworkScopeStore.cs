/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Data.Entity.Infrastructure;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFramework.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Provides methods allowing to manage the scopes stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkScopeStore :
    OpenIddictEntityFrameworkScopeStore<OpenIddictEntityFrameworkScope, string>
{
    public OpenIddictEntityFrameworkScopeStore(
        IMemoryCache cache,
        IOpenIddictEntityFrameworkContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
        : base(cache, context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the scopes stored in a database.
/// </summary>
/// <typeparam name="TScope">The type of the scope entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkScopeStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictScopeStore<TScope>
    where TScope : OpenIddictEntityFrameworkScope<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkScopeStore(
        IMemoryCache cache,
        IOpenIddictEntityFrameworkContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Gets the memory cache associated with the current store.
    /// </summary>
    protected IMemoryCache Cache { get; }

    /// <summary>
    /// Gets the database context associated with the current store.
    /// </summary>
    protected IOpenIddictEntityFrameworkContext Context { get; }

    /// <summary>
    /// Gets the options associated with the current store.
    /// </summary>
    protected IOptionsMonitor<OpenIddictEntityFrameworkOptions> Options { get; }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        return await context.Set<TScope>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TScope>(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TScope>().Add(scope);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TScope>().Remove(scope);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            context.Entry(scope).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TScope?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        return await context.Set<TScope>().FindAsync(cancellationToken, [key]);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TScope?> FindByNameAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return GetTrackedEntity() is TScope scope ? scope : await QueryAsync();

        TScope? GetTrackedEntity() =>
            (from entry in context.ChangeTracker.Entries<TScope>()
             where string.Equals(entry.Entity.Name, name, StringComparison.Ordinal)
             select entry.Entity).FirstOrDefault();

        Task<TScope?> QueryAsync() =>
            (from scope in context.Set<TScope>()
             where scope.Name == name
             select scope).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TScope> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
    {
        if (names.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0203), nameof(names));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            // Note: Enumerable.Contains() is deliberately used without the extension method syntax to ensure
            // ImmutableArray.Contains() (which is not fully supported by Entity Framework 6.x) is not used instead.
            var scopes = from scope in context.Set<TScope>()
                         where Enumerable.Contains(names, scope.Name)
                         select scope;

            using var enumerator = ((IDbAsyncEnumerable<TScope>) scopes).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TScope> FindByResourceAsync(string resource, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(resource);

        // To optimize the efficiency of the query a bit, only scopes whose stringified
        // Resources column contains the specified resource are returned. Once the scopes
        // are retrieved, a second pass is made to ensure only valid elements are returned.
        // Implementers that use this method in a hot path may want to override this method
        // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var scopes = from scope in context.Set<TScope>()
                         where scope.Resources!.Contains(resource)
                         select scope;

            using var enumerator = ((IDbAsyncEnumerable<TScope>) scopes).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                var resources = await GetResourcesAsync(enumerator.Current, cancellationToken);
                if (resources.Contains(resource, StringComparer.Ordinal))
                {
                    yield return enumerator.Current;
                }
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TScope>(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetDescriptionAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return new(scope.Description);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (string.IsNullOrEmpty(scope.Descriptions))
        {
            return new([]);
        }

        // Note: parsing the stringified descriptions is an expensive operation.
        // To mitigate that, the resulting object is stored in the memory cache.
        var key = string.Concat("42891062-8f69-43ba-9111-db7e8ded2553", "\x1e", scope.Descriptions);
        var descriptions = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(scope.Descriptions);
            var builder = ImmutableDictionary.CreateBuilder<CultureInfo, string>();

            foreach (var property in document.RootElement.EnumerateObject())
            {
                var value = property.Value.GetString();
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                builder[CultureInfo.GetCultureInfo(property.Name)] = value;
            }

            return builder.ToImmutable();
        })!;

        return new(descriptions);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetDisplayNameAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return new(scope.DisplayName);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (string.IsNullOrEmpty(scope.DisplayNames))
        {
            return new([]);
        }

        // Note: parsing the stringified display names is an expensive operation.
        // To mitigate that, the resulting object is stored in the memory cache.
        var key = string.Concat("e17d437b-bdd2-43f3-974e-46d524f4bae1", "\x1e", scope.DisplayNames);
        var names = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(scope.DisplayNames);
            var builder = ImmutableDictionary.CreateBuilder<CultureInfo, string>();

            foreach (var property in document.RootElement.EnumerateObject())
            {
                var value = property.Value.GetString();
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                builder[CultureInfo.GetCultureInfo(property.Name)] = value;
            }

            return builder.ToImmutable();
        })!;

        return new(names);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return new(ConvertIdentifierToString(scope.Id));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetNameAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return new(scope.Name);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (string.IsNullOrEmpty(scope.Properties))
        {
            return new([]);
        }

        // Note: parsing the stringified properties is an expensive operation.
        // To mitigate that, the resulting object is stored in the memory cache.
        var key = string.Concat("78d8dfdd-3870-442e-b62e-dc9bf6eaeff7", "\x1e", scope.Properties);
        var properties = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(scope.Properties);
            var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);

            foreach (var property in document.RootElement.EnumerateObject())
            {
                builder[property.Name] = property.Value.Clone();
            }

            return builder.ToImmutable();
        })!;

        return new(properties);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetResourcesAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (string.IsNullOrEmpty(scope.Resources))
        {
            return new([]);
        }

        // Note: parsing the stringified resources is an expensive operation.
        // To mitigate that, the resulting array is stored in the memory cache.
        var key = string.Concat("b6148250-aede-4fb9-a621-07c9bcf238c3", "\x1e", scope.Resources);
        var resources = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(scope.Resources);
            var builder = ImmutableArray.CreateBuilder<string>(document.RootElement.GetArrayLength());

            foreach (var element in document.RootElement.EnumerateArray())
            {
                var value = element.GetString();
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                builder.Add(value);
            }

            return builder.ToImmutable();
        });

        return new(resources);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TScope> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TScope>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TScope>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TScope> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TScope> query = context.Set<TScope>().OrderBy(static scope => scope.Id!);

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        using var enumerator = ((IDbAsyncEnumerable<TScope>) query).GetAsyncEnumerator();

        while (await enumerator.MoveNextAsync(cancellationToken))
        {
            yield return enumerator.Current;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TScope>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            using var enumerator = ((IDbAsyncEnumerable<TResult>) query(context.Set<TScope>(), state)).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDescriptionAsync(TScope scope, string? description, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        scope.Description = description;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDescriptionsAsync(TScope scope,
        ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (descriptions is not { IsEmpty: false })
        {
            scope.Descriptions = null;

            return ValueTask.CompletedTask;
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

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDisplayNameAsync(TScope scope, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        scope.DisplayName = name;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDisplayNamesAsync(TScope scope,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (names is not { IsEmpty: false })
        {
            scope.DisplayNames = null;

            return ValueTask.CompletedTask;
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

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetNameAsync(TScope scope, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        scope.Name = name;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TScope scope,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (properties is not { IsEmpty: false })
        {
            scope.Properties = null;

            return ValueTask.CompletedTask;
        }

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        });

        writer.WriteStartObject();

        foreach (var property in properties)
        {
            writer.WritePropertyName(property.Key);
            property.Value.WriteTo(writer);
        }

        writer.WriteEndObject();
        writer.Flush();

        scope.Properties = Encoding.UTF8.GetString(stream.ToArray());

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetResourcesAsync(TScope scope, ImmutableArray<string> resources, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        if (resources.IsDefaultOrEmpty)
        {
            scope.Resources = null;

            return ValueTask.CompletedTask;
        }

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        });

        writer.WriteStartArray();

        foreach (var resource in resources)
        {
            writer.WriteStringValue(resource);
        }

        writer.WriteEndArray();
        writer.Flush();

        scope.Resources = Encoding.UTF8.GetString(stream.ToArray());

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TScope>().Attach(scope);

        // Generate a new concurrency token and attach it
        // to the scope before persisting the changes.
        scope.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Entry(scope).State = EntityState.Modified;

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            context.Entry(scope).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
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

        // Optimization: if the key is a string, directly return it as-is.
        if (typeof(TKey) == typeof(string))
        {
            return (TKey?) (object?) identifier;
        }

        var converter =
#if NET
            TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));
#else
            TypeDescriptor.GetConverter(typeof(TKey));
#endif

        return (TKey?) converter.ConvertFromInvariantString(identifier);
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

        // Optimization: if the key is a string, directly return it as-is.
        if (identifier is string value)
        {
            return value;
        }

        var converter =
#if NET
            TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));
#else
            TypeDescriptor.GetConverter(typeof(TKey));
#endif

        return converter.ConvertToInvariantString(identifier);
    }
}
