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
/// Provides methods allowing to manage the scopes stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkCoreScopeStore :
    OpenIddictEntityFrameworkCoreScopeStore<OpenIddictEntityFrameworkCoreScope, string>
{
    public OpenIddictEntityFrameworkCoreScopeStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the scopes stored in a database.
/// </summary>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreScopeStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> :
    OpenIddictEntityFrameworkCoreScopeStore<OpenIddictEntityFrameworkCoreScope<TKey>, TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreScopeStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the scopes stored in a database.
/// </summary>
/// <typeparam name="TScope">The type of the scope entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreScopeStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TScope,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictScopeStore<TScope>
    where TScope : OpenIddictEntityFrameworkCoreScope<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreScopeStore(
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

        context.Add(scope);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Remove(scope);

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

        return await context.Set<TScope>().FindAsync([key], cancellationToken);
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
            (from scope in context.Set<TScope>().AsTracking()
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

            await foreach (var scope in (
                from scope in context.Set<TScope>().AsTracking()
                where names.Contains(scope.Name!)
                select scope).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return scope;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TScope> FindByResourceAsync(string resource, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(resource);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var scope in (from scope in context.Set<TScope>().AsTracking()
                                         where scope.Resources!.Contains(resource)
                                         select scope).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return scope;
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

        return await query(context.Set<TScope>().AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
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

        return new(scope.Descriptions is { Count: > 0 } descriptions
            ? descriptions.ToImmutableDictionary(static pair => CultureInfo.GetCultureInfo(pair.Key), static pair => pair.Value)
            : ImmutableDictionary.Create<CultureInfo, string>());
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

        return new(scope.DisplayNames is { Count: > 0 } names
            ? names.ToImmutableDictionary(static pair => CultureInfo.GetCultureInfo(pair.Key), static pair => pair.Value)
            : []);
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

        return new(scope.Properties is { Count: > 0 } properties ? [.. properties] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetResourcesAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        return new(scope.Resources is { Length: > 0 } resources ? [.. resources] : []);
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

        var query = context.Set<TScope>().OrderBy(scope => scope.Id!).AsTracking();

        if (offset.HasValue)
        {
            query = query.Skip(offset.Value);
        }

        if (count.HasValue)
        {
            query = query.Take(count.Value);
        }

        await foreach (var scope in query.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return scope;
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

            await foreach (var scope in query(context.Set<TScope>().AsTracking(), state).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return scope;
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

        scope.Descriptions = descriptions is { IsEmpty: false }
            ? descriptions.ToImmutableDictionary(static pair => pair.Key.Name, static pair => pair.Value)
            : null;

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

        scope.DisplayNames = names is { IsEmpty: false }
            ? names.ToImmutableDictionary(static pair => pair.Key.Name, static pair => pair.Value)
            : null;

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

        scope.Properties = properties;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetResourcesAsync(TScope scope, ImmutableArray<string> resources, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        scope.Resources = resources is { IsDefaultOrEmpty: false } ? [.. resources] : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TScope scope, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Attach(scope);

        // Generate a new concurrency token and attach it
        // to the scope before persisting the changes.
        scope.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Update(scope);

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
