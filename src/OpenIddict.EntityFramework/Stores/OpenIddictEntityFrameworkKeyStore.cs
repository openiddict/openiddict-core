/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Data.Entity.Infrastructure;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFramework.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Provides methods allowing to manage the keys stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkKeyStore : OpenIddictEntityFrameworkKeyStore<OpenIddictEntityFrameworkKey, string>
{
    public OpenIddictEntityFrameworkKeyStore(
        IOpenIddictEntityFrameworkContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the keys stored in a database.
/// </summary>
/// <typeparam name="TEntity">The type of the key entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkKeyStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TEntity,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictKeyStore<TEntity>
    where TEntity : OpenIddictEntityFrameworkKey<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkKeyStore(
        IOpenIddictEntityFrameworkContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Options = options ?? throw new ArgumentNullException(nameof(options));
    }

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

        return await context.Set<TEntity>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TEntity>().Add(key);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TEntity>().Remove(key);

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

        return await context.Set<TEntity>().FindAsync(cancellationToken, [ConvertIdentifierFromString(identifier)]);
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

        if (string.IsNullOrEmpty(key.Properties))
        {
            return new([]);
        }

        using var document = JsonDocument.Parse(key.Properties);
        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);

        foreach (var property in document.RootElement.EnumerateObject())
        {
            builder[property.Name] = property.Value.Clone();
        }

        return new(builder.ToImmutable());
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

        IQueryable<TEntity> query = context.Set<TEntity>().OrderBy(static key => key.Id!);

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        using var enumerator = ((IDbAsyncEnumerable<TEntity>) query).GetAsyncEnumerator();

        while (await enumerator.MoveNextAsync(cancellationToken))
        {
            yield return enumerator.Current;
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

        // Note: Entity Framework 6.x doesn't support set-based deletes. Since the number
        // of keys is expected to be small, they are materialized and removed in a single batch.
        var keys = await query.ToListAsync(cancellationToken);
        if (keys.Count is 0)
        {
            return 0;
        }

        context.Set<TEntity>().RemoveRange(keys);

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

        if (properties is not { IsEmpty: false })
        {
            key.Properties = null;

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

        key.Properties = Encoding.UTF8.GetString(stream.ToArray());

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

        context.Set<TEntity>().Attach(key);

        // Generate a new concurrency token and attach it
        // to the key before persisting the changes.
        key.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Entry(key).State = EntityState.Modified;

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

    private static DateTimeOffset? ToDateTimeOffset(DateTime? date)
        => date is DateTime value ? new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)) : null;
}
