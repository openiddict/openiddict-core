/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Provides methods allowing to manage the resources stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkCoreResourceStore : OpenIddictEntityFrameworkCoreResourceStore<OpenIddictEntityFrameworkCoreResource, string>
{
    public OpenIddictEntityFrameworkCoreResourceStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the resources stored in a database.
/// </summary>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreResourceStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : OpenIddictEntityFrameworkCoreResourceStore<OpenIddictEntityFrameworkCoreResource<TKey>, TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreResourceStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the resources stored in a database.
/// </summary>
/// <typeparam name="TResource">The type of the resource entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreResourceStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TResource,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictResourceStore<TResource>
    where TResource : OpenIddictEntityFrameworkCoreResource<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreResourceStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Gets the database context associated with the current store.
    /// </summary>
    protected IOpenIddictEntityFrameworkCoreContext Context { get; }

    /// <summary>
    /// Gets the options associated with the current store.
    /// </summary>
    protected IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> Options { get; }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        return await context.Set<TResource>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TResource>(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Add(resource);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Remove(resource);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            context.Entry(resource).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResource?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        return await context.Set<TResource>().FindAsync([key], cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResource?> FindByNameAsync(string name, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return GetTrackedEntity() is TResource resource ? resource : await QueryAsync();

        TResource? GetTrackedEntity() =>
            (from entry in context.ChangeTracker.Entries<TResource>()
             where string.Equals(entry.Entity.Name, name, StringComparison.Ordinal)
             select entry.Entity).FirstOrDefault();

        Task<TResource?> QueryAsync() =>
            (from resource in context.Set<TResource>().AsTracking()
             where resource.Name == name
             select resource).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResource> FindByNamesAsync(ImmutableArray<string> names, CancellationToken cancellationToken)
    {
        if (names.Any(string.IsNullOrEmpty))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0203), nameof(names));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResource> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var resource in (
                from resource in context.Set<TResource>().AsTracking()
                where names.Contains(resource.Name!)
                select resource).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return resource;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TResource>().AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetDescriptionAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new(resource.Description);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new(resource.Descriptions is { Count: > 0 } descriptions
            ? descriptions.ToImmutableDictionary(static pair => CultureInfo.GetCultureInfo(pair.Key), static pair => pair.Value)
            : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetDisplayNameAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new(resource.DisplayName);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new(resource.DisplayNames is { Count: > 0 } names
            ? names.ToImmutableDictionary(static pair => CultureInfo.GetCultureInfo(pair.Key), static pair => pair.Value)
            : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new(ConvertIdentifierToString(resource.Id));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetNameAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new(resource.Name);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        return new(resource.Properties is { Count: > 0 } properties ? [.. properties] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TResource> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TResource>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TResource>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TResource> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        var query = context.Set<TResource>().OrderBy(resource => resource.Id!).AsTracking();

        if (offset.HasValue)
        {
            query = query.Skip(offset.Value);
        }

        if (count.HasValue)
        {
            query = query.Take(count.Value);
        }

        await foreach (var resource in query.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return resource;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TResource>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var resource in query(context.Set<TResource>().AsTracking(), state).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return resource;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDescriptionAsync(TResource resource, string? description, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        resource.Description = description;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDescriptionsAsync(TResource resource,
        ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        resource.Descriptions = descriptions is { IsEmpty: false }
            ? descriptions.ToImmutableDictionary(static pair => pair.Key.Name, static pair => pair.Value)
            : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDisplayNameAsync(TResource resource, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        resource.DisplayName = name;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDisplayNamesAsync(TResource resource,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        resource.DisplayNames = names is { IsEmpty: false }
            ? names.ToImmutableDictionary(static pair => pair.Key.Name, static pair => pair.Value)
            : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetNameAsync(TResource resource, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        resource.Name = name;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TResource resource,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        resource.Properties = properties;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TResource resource, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resource);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Attach(resource);

        // Generate a new concurrency token and attach it
        // to the resource before persisting the changes.
        resource.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Update(resource);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            context.Entry(resource).State = EntityState.Unchanged;

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

        else
        {
            var converter = TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));

            return (TKey?) converter.ConvertFromInvariantString(identifier);
        }
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

        else
        {
            var converter = TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));

            return converter.ConvertToInvariantString(identifier);
        }
    }
}
