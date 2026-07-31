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
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
public class OpenIddictMongoDbTokenStore : OpenIddictMongoDbTokenStore<OpenIddictMongoDbToken>
{
    public OpenIddictMongoDbTokenStore(
        IOpenIddictMongoDbContext context,
        IOptionsMonitor<OpenIddictMongoDbOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the tokens stored in a database.
/// </summary>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
public class OpenIddictMongoDbTokenStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken> : IOpenIddictTokenStore<TToken>
    where TToken : OpenIddictMongoDbToken
{
    public OpenIddictMongoDbTokenStore(
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
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return await collection.CountDocumentsAsync(FilterDefinition<TToken>.Empty, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return await query(collection.AsQueryable(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        await collection.InsertOneAsync(token, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        if ((await collection.DeleteOneAsync(entity =>
            entity.Id == token.Id &&
            entity.ConcurrencyToken == token.ConcurrencyToken, cancellationToken)).DeletedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TToken> FindAsync(
        (string? Subject, string? ApplicationId, string? Status, string? Type) query,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        IQueryable<TToken> tokens = collection.AsQueryable();

        if (!string.IsNullOrEmpty(query.Subject))
        {
            tokens = tokens.Where(token => token.Subject == query.Subject);
        }

        if (!string.IsNullOrEmpty(query.ApplicationId))
        {
            tokens = tokens.Where(token => token.ApplicationId == ObjectId.Parse(query.ApplicationId));
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            tokens = tokens.Where(token => token.Status == query.Status);
        }

        if (!string.IsNullOrEmpty(query.Type))
        {
            tokens = tokens.Where(token => token.Type == query.Type);
        }

        await foreach (var token in tokens.ToAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return token;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

            await foreach (var token in collection.Find(token =>
                token.ApplicationId == ObjectId.Parse(identifier)).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return token;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

            await foreach (var token in collection.Find(token =>
                token.AuthorizationId == ObjectId.Parse(identifier)).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return token;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return await collection.Find(token => token.Id == ObjectId.Parse(identifier)).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return await collection.Find(token => token.ReferenceId == identifier).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TToken> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

            await foreach (var token in collection.Find(token => token.Subject == subject).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return token;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetApplicationIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.ApplicationId != ObjectId.Empty ? token.ApplicationId.ToString() : null);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return await query(collection.AsQueryable(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetAuthorizationIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.AuthorizationId != ObjectId.Empty ? token.AuthorizationId.ToString() : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.CreationDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetExpirationDateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.ExpirationDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Id.ToString());
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetPayloadAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Payload);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (token.Properties is null)
        {
            return new([]);
        }

        using var document = JsonDocument.Parse(token.Properties.ToJson());
        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);

        foreach (var property in document.RootElement.EnumerateObject())
        {
            builder[property.Name] = property.Value.Clone();
        }

        return new(builder.ToImmutable());
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetRedemptionDateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.RedemptionDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetReferenceIdAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.ReferenceId);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Status);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetSubjectAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Subject);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetTypeAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        return new(token.Type);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TToken> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TToken>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TToken>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TToken> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        var query = (IQueryable<TToken>) collection.AsQueryable().OrderBy(token => token.Id);

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var token in ((IAsyncCursorSource<TToken>) query).ToAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return token;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TToken>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

            await foreach (var element in query(collection.AsQueryable(), state).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return element;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        var result = 0L;

        // Note: directly deleting the resulting set of an aggregate query is not supported by MongoDB.
        // To work around this limitation, the token identifiers are stored in an intermediate list
        // and delete requests are sent to remove the documents corresponding to these identifiers.

        var identifiers =
            await (from token in collection.AsQueryable()
                   join authorization in database.GetCollection<OpenIddictMongoDbAuthorization>(Options.CurrentValue.AuthorizationsCollectionName).AsQueryable()
                                      on token.AuthorizationId equals authorization.Id into authorizations
                   where token.CreationDate < threshold.UtcDateTime
                   where (token.Status != Statuses.Inactive && token.Status != Statuses.Valid) ||
                          token.ExpirationDate < DateTime.UtcNow ||
                          authorizations.Any(token => token.Status != Statuses.Valid)
                   select token.Id).ToListAsync(cancellationToken);

        // Note: to avoid generating delete requests with very large filters, chunking is used here and the
        // maximum number of elements that can be removed by a single call to PruneAsync() is deliberately limited.
        foreach (var chunk in identifiers.Take(1_000_000).Chunk(1_000))
        {
            result += (await collection.DeleteManyAsync(token => chunk.Contains(token.Id), cancellationToken)).DeletedCount;
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        var filter = Builders<TToken>.Filter.Empty;

        if (!string.IsNullOrEmpty(subject))
        {
            filter &= Builders<TToken>.Filter.Where(token => token.Subject == subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            filter &= Builders<TToken>.Filter.Where(token => token.ApplicationId == ObjectId.Parse(client));
        }

        if (!string.IsNullOrEmpty(status))
        {
            filter &= Builders<TToken>.Filter.Where(token => token.Status == status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            filter &= Builders<TToken>.Filter.Where(token => token.Type == type);
        }

        return (await collection.UpdateManyAsync(
            filter           : filter,
            update           : Builders<TToken>.Update.Set(token => token.Status, Statuses.Revoked),
            options          : null,
            cancellationToken: cancellationToken)).MatchedCount;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return (await collection.UpdateManyAsync(
            filter           : token => token.ApplicationId == ObjectId.Parse(identifier),
            update           : Builders<TToken>.Update.Set(token => token.Status, Statuses.Revoked),
            options          : null,
            cancellationToken: cancellationToken)).MatchedCount;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return (await collection.UpdateManyAsync(
            filter           : token => token.AuthorizationId == ObjectId.Parse(identifier),
            update           : Builders<TToken>.Update.Set(token => token.Status, Statuses.Revoked),
            options          : null,
            cancellationToken: cancellationToken)).MatchedCount;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        return (await collection.UpdateManyAsync(
            filter           : token => token.Subject == subject,
            update           : Builders<TToken>.Update.Set(token => token.Status, Statuses.Revoked),
            options          : null,
            cancellationToken: cancellationToken)).MatchedCount;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetApplicationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.ApplicationId = !string.IsNullOrEmpty(identifier) ? ObjectId.Parse(identifier) : ObjectId.Empty;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetAuthorizationIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.AuthorizationId = !string.IsNullOrEmpty(identifier) ? ObjectId.Parse(identifier) : ObjectId.Empty;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.CreationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetExpirationDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.ExpirationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPayloadAsync(TToken token, string? payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Payload = payload;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TToken token,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        if (properties is not { IsEmpty: false })
        {
            token.Properties = null;

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

        token.Properties = BsonDocument.Parse(Encoding.UTF8.GetString(stream.ToArray()));

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRedemptionDateAsync(TToken token, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.RedemptionDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetReferenceIdAsync(TToken token, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.ReferenceId = identifier;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TToken token, string? status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Status = status;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSubjectAsync(TToken token, string? subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Subject = subject;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetTypeAsync(TToken token, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        token.Type = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TToken token, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(token);

        // Generate a new concurrency token and attach it
        // to the token before persisting the changes.
        var timestamp = token.ConcurrencyToken;
        token.ConcurrencyToken = Guid.NewGuid().ToString();

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TToken>(Options.CurrentValue.TokensCollectionName);

        if ((await collection.ReplaceOneAsync(entity =>
            entity.Id == token.Id &&
            entity.ConcurrencyToken == timestamp, token, null as ReplaceOptions, cancellationToken)).MatchedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }
}
