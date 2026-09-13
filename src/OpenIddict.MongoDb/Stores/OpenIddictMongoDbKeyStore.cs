/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Options;
using OpenIddict.MongoDb.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.MongoDb;

/// <summary>
/// Provides methods allowing to manage the keys stored in a database.
/// </summary>
public class OpenIddictMongoDbKeyStore : OpenIddictMongoDbKeyStore<OpenIddictMongoDbKey>
{
    public OpenIddictMongoDbKeyStore(
        IOpenIddictMongoDbContext context,
        IOptionsMonitor<OpenIddictMongoDbOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the keys stored in a database.
/// </summary>
/// <typeparam name="TEntity">The type of the key entity.</typeparam>
public class OpenIddictMongoDbKeyStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TEntity> : IOpenIddictKeyStore<TEntity>
    where TEntity : OpenIddictMongoDbKey
{
    public OpenIddictMongoDbKeyStore(
        IOpenIddictMongoDbContext context,
        IOptionsMonitor<OpenIddictMongoDbOptions> options)
    {
        Context = context ?? throw new ArgumentNullException(nameof(context));
        Options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <summary>
    /// Gets the database context associated with the current store.
    /// </summary>
    protected IOpenIddictMongoDbContext Context { get; }

    /// <summary>
    /// Gets the options associated with the current store.
    /// </summary>
    protected IOptionsMonitor<OpenIddictMongoDbOptions> Options { get; }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
    {
        var collection = await GetCollectionAsync(cancellationToken);

        return await collection.CountDocumentsAsync(FilterDefinition<TEntity>.Empty, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        var collection = await GetCollectionAsync(cancellationToken);

        await collection.InsertOneAsync(key, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TEntity key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        var collection = await GetCollectionAsync(cancellationToken);

        if ((await collection.DeleteOneAsync(entity =>
            entity.Id == key.Id &&
            entity.ConcurrencyToken == key.ConcurrencyToken, cancellationToken)).DeletedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TEntity?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var collection = await GetCollectionAsync(cancellationToken);

        return await collection.Find(key => key.Id == ObjectId.Parse(identifier)).FirstOrDefaultAsync(cancellationToken);
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
        => new((key ?? throw new ArgumentNullException(nameof(key))).Id.ToString());

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

        if (key.Properties is null)
        {
            return new([]);
        }

        using var document = JsonDocument.Parse(key.Properties.ToJson());
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
    public virtual async IAsyncEnumerable<TEntity> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var collection = await GetCollectionAsync(cancellationToken);

        var query = (IQueryable<TEntity>) collection.AsQueryable().OrderBy(static key => key.Id);

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var key in ((IAsyncCursorSource<TEntity>) query).ToAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return key;
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        var collection = await GetCollectionAsync(cancellationToken);

        var date = threshold.UtcDateTime;

        return (await collection.DeleteManyAsync(key => key.RetirementDate < date ||
            (key.Status != Statuses.Valid && key.CreationDate < date), cancellationToken)).DeletedCount;
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

        key.Properties = BsonDocument.Parse(Encoding.UTF8.GetString(stream.ToArray()));

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

        // Generate a new concurrency token and attach it
        // to the key before persisting the changes.
        var timestamp = key.ConcurrencyToken;
        key.ConcurrencyToken = Guid.NewGuid().ToString();

        var collection = await GetCollectionAsync(cancellationToken);

        if ((await collection.ReplaceOneAsync(entity =>
            entity.Id == key.Id &&
            entity.ConcurrencyToken == timestamp, key, null as ReplaceOptions, cancellationToken)).MatchedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }

    private static DateTimeOffset? ToDateTimeOffset(DateTime? date)
        => date is DateTime value ? new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)) : null;

    private async ValueTask<IMongoCollection<TEntity>> GetCollectionAsync(CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);

        return database.GetCollection<TEntity>(Options.CurrentValue.KeysCollectionName);
    }
}
