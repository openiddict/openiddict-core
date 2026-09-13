/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Provides methods allowing to manage the keys stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkCoreKeyStore : OpenIddictEntityFrameworkCoreKeyStore<OpenIddictEntityFrameworkCoreKey<string>, string>
{
    public OpenIddictEntityFrameworkCoreKeyStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the keys stored in a database.
/// </summary>
/// <typeparam name="TEntity">The type of the key entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreKeyStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TEntity,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictKeyStore<TEntity>
    where TEntity : OpenIddictEntityFrameworkCoreKey<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreKeyStore(
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

        return await context.Set<TEntity>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        // Note: unlike other entities, keys don't have a non-generic default entity
        // whose constructor generates an identifier: generate it here if necessary.
        if (key.Id is null && typeof(TKey) == typeof(string))
        {
            key.Id = (TKey) (object) Guid.NewGuid().ToString();
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Add(key);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Remove(key);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls from failing.
            context.Entry(key).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TEntity?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await context.Set<TEntity>().FindAsync([ConvertIdentifierFromString(identifier)], cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetActivationDateAsync(TEntity key, CancellationToken cancellationToken)
        => new(ToDateTimeOffset((key ?? throw new ArgumentNullException(nameof(key))).ActivationDate));

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetAlgorithmAsync(TEntity key, CancellationToken cancellationToken)
        => new((key ?? throw new ArgumentNullException(nameof(key))).Algorithm);

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TEntity key, CancellationToken cancellationToken)
        => new(ToDateTimeOffset((key ?? throw new ArgumentNullException(nameof(key))).CreationDate));

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetExpirationDateAsync(TEntity key, CancellationToken cancellationToken)
        => new(ToDateTimeOffset((key ?? throw new ArgumentNullException(nameof(key))).ExpirationDate));

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TEntity key, CancellationToken cancellationToken)
        => new(ConvertIdentifierToString((key ?? throw new ArgumentNullException(nameof(key))).Id));

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetKeyIdAsync(TEntity key, CancellationToken cancellationToken)
        => new((key ?? throw new ArgumentNullException(nameof(key))).KeyId);

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetPayloadAsync(TEntity key, CancellationToken cancellationToken)
        => new((key ?? throw new ArgumentNullException(nameof(key))).Payload);

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        return new(key.Properties is { Count: > 0 } properties ? [.. properties] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetRetirementDateAsync(TEntity key, CancellationToken cancellationToken)
        => new(ToDateTimeOffset((key ?? throw new ArgumentNullException(nameof(key))).RetirementDate));

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TEntity key, CancellationToken cancellationToken)
        => new((key ?? throw new ArgumentNullException(nameof(key))).Status);

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetUsageAsync(TEntity key, CancellationToken cancellationToken)
        => new((key ?? throw new ArgumentNullException(nameof(key))).Usage);

    /// <inheritdoc/>
    public virtual ValueTask<TEntity> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TEntity>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TEntity>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TEntity> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        var query = context.Set<TEntity>().OrderBy(static key => key.Id!).AsTracking();

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var key in query.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return key;
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
        // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
        var date = threshold.UtcDateTime;

        var query = from key in context.Set<TEntity>()
                    where key.RetirementDate < date || (key.Status != Statuses.Valid && key.CreationDate < date)
                    select key;

        if (!Options.CurrentValue.DisableBulkOperations)
        {
            return await query.ExecuteDeleteAsync(cancellationToken);
        }

        // Note: the number of keys is expected to be small, so they are removed in a single batch.
        var keys = await query.AsTracking().ToListAsync(cancellationToken);
        if (keys.Count is 0)
        {
            return 0;
        }

        context.RemoveRange(keys);

        await context.SaveChangesAsync(cancellationToken);

        return keys.Count;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetActivationDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.ActivationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetAlgorithmAsync(TEntity key, string? algorithm, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.Algorithm = algorithm;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.CreationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetExpirationDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.ExpirationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetKeyIdAsync(TEntity key, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.KeyId = identifier;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPayloadAsync(TEntity key, string? payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.Payload = payload;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TEntity key,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.Properties = properties;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRetirementDateAsync(TEntity key, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.RetirementDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TEntity key, string? status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.Status = status;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetUsageAsync(TEntity key, string? usage, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        key.Usage = usage;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Attach(key);

        // Generate a new concurrency token and attach it
        // to the key before persisting the changes.
        key.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Update(key);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls from failing.
            context.Entry(key).State = EntityState.Unchanged;

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

        return (TKey?) TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey)).ConvertFromInvariantString(identifier);
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

        return TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey)).ConvertToInvariantString(identifier);
    }

    private static DateTimeOffset? ToDateTimeOffset(DateTime? date)
        => date is DateTime value ? new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)) : null;
}
