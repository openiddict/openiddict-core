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
/// Provides methods allowing to manage the authorizations stored in a database.
/// </summary>
public class OpenIddictMongoDbAuthorizationStore : OpenIddictMongoDbAuthorizationStore<OpenIddictMongoDbAuthorization>
{
    public OpenIddictMongoDbAuthorizationStore(
        IOpenIddictMongoDbContext context,
        IOptionsMonitor<OpenIddictMongoDbOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the authorizations stored in a database.
/// </summary>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
public class OpenIddictMongoDbAuthorizationStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization> : IOpenIddictAuthorizationStore<TAuthorization>
    where TAuthorization : OpenIddictMongoDbAuthorization
{
    public OpenIddictMongoDbAuthorizationStore(
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
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        return await collection.CountDocumentsAsync(FilterDefinition<TAuthorization>.Empty, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        return await query(collection.AsQueryable(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        await collection.InsertOneAsync(authorization, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        if ((await collection.DeleteOneAsync(entity =>
            entity.Id == authorization.Id &&
            entity.ConcurrencyToken == authorization.ConcurrencyToken, cancellationToken)).DeletedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }

        // Delete the tokens associated with the authorization.
        await database.GetCollection<OpenIddictMongoDbToken>(Options.CurrentValue.TokensCollectionName)
            .DeleteManyAsync(token => token.AuthorizationId == authorization.Id, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TAuthorization> FindAsync(
        (string? Subject, string? ApplicationId, string? Status,
         string? Type, ImmutableArray<string>? RequiredScopes) query, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        IQueryable<TAuthorization> authorizations = collection.AsQueryable();

        if (!string.IsNullOrEmpty(query.Subject))
        {
            authorizations = authorizations.Where(authorization => authorization.Subject == query.Subject);
        }

        if (!string.IsNullOrEmpty(query.ApplicationId))
        {
            authorizations = authorizations.Where(authorization => authorization.ApplicationId == ObjectId.Parse(query.ApplicationId));
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            authorizations = authorizations.Where(authorization => authorization.Status == query.Status);
        }

        if (!string.IsNullOrEmpty(query.Type))
        {
            authorizations = authorizations.Where(authorization => authorization.Type == query.Type);
        }

        if (query.RequiredScopes is { IsDefaultOrEmpty: false } scopes)
        {
            authorizations = authorizations.Where(authorization => scopes.All(scope => authorization.Scopes!.Contains(scope)));
        }

        await foreach (var authorization in authorizations.ToAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return authorization;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TAuthorization> FindByApplicationIdAsync(
        string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

            await foreach (var authorization in collection.Find(authorization =>
                authorization.ApplicationId == ObjectId.Parse(identifier)).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        return await collection.Find(authorization => authorization.Id == ObjectId.Parse(identifier))
            .FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TAuthorization> FindBySubjectAsync(
        string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

            await foreach (var authorization in collection.Find(authorization =>
                authorization.Subject == subject).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetApplicationIdAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        return new(authorization.ApplicationId != ObjectId.Empty ? authorization.ApplicationId.ToString() : null);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        return await query(collection.AsQueryable(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        return new(authorization.CreationDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        return new(authorization.Id.ToString());
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        if (authorization.Properties is null)
        {
            return new([]);
        }

        using var document = JsonDocument.Parse(authorization.Properties.ToJson());
        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);

        foreach (var property in document.RootElement.EnumerateObject())
        {
            builder[property.Name] = property.Value.Clone();
        }

        return new(builder.ToImmutable());
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetScopesAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        return new(authorization.Scopes is { IsDefaultOrEmpty: false } scopes ? scopes : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        return new(authorization.Status);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetSubjectAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        return new(authorization.Subject);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetTypeAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        return new(authorization.Type);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TAuthorization> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TAuthorization>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TAuthorization>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TAuthorization> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        var query = (IQueryable<TAuthorization>) collection.AsQueryable().OrderBy(authorization => authorization.Id);

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var authorization in ((IAsyncCursorSource<TAuthorization>) query).ToAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return authorization;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

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
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        var result = 0L;

        // Note: directly deleting the resulting set of an aggregate query is not supported by MongoDB.
        // To work around this limitation, the authorization identifiers are stored in an intermediate
        // list and delete requests are sent to remove the documents corresponding to these identifiers.

        var identifiers =
            await (from authorization in collection.AsQueryable()
                   join token in database.GetCollection<OpenIddictMongoDbToken>(Options.CurrentValue.TokensCollectionName).AsQueryable()
                              on authorization.Id equals token.AuthorizationId into tokens
                   where authorization.CreationDate < threshold.UtcDateTime
                   where authorization.Status != Statuses.Valid || authorization.Type == AuthorizationTypes.AdHoc
                   where !tokens.Any()
                   select authorization.Id).ToListAsync(cancellationToken);

        // Note: to avoid generating delete requests with very large filters, chunking is used here and the
        // maximum number of elements that can be removed by a single call to PruneAsync() is deliberately limited.
        foreach (var chunk in identifiers.Take(1_000_000).Chunk(1_000))
        {
            result += (await collection.DeleteManyAsync(authorization => chunk.Contains(authorization.Id), cancellationToken)).DeletedCount;
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        var filter = Builders<TAuthorization>.Filter.Empty;

        if (!string.IsNullOrEmpty(subject))
        {
            filter &= Builders<TAuthorization>.Filter.Where(authorization => authorization.Subject == subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            filter &= Builders<TAuthorization>.Filter.Where(authorization => authorization.ApplicationId == ObjectId.Parse(client));
        }

        if (!string.IsNullOrEmpty(status))
        {
            filter &= Builders<TAuthorization>.Filter.Where(authorization => authorization.Status == status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            filter &= Builders<TAuthorization>.Filter.Where(authorization => authorization.Type == type);
        }

        return (await collection.UpdateManyAsync(
            filter           : filter,
            update           : Builders<TAuthorization>.Update.Set(authorization => authorization.Status, Statuses.Revoked),
            options          : null,
            cancellationToken: cancellationToken)).MatchedCount;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        return (await collection.UpdateManyAsync(
            filter           : authorization => authorization.ApplicationId == ObjectId.Parse(identifier),
            update           : Builders<TAuthorization>.Update.Set(authorization => authorization.Status, Statuses.Revoked),
            options          : null,
            cancellationToken: cancellationToken)).MatchedCount;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        return (await collection.UpdateManyAsync(
            filter           : authorization => authorization.Subject == subject,
            update           : Builders<TAuthorization>.Update.Set(authorization => authorization.Status, Statuses.Revoked),
            options          : null,
            cancellationToken: cancellationToken)).MatchedCount;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetApplicationIdAsync(TAuthorization authorization,
        string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        authorization.ApplicationId = !string.IsNullOrEmpty(identifier) ? ObjectId.Parse(identifier) : ObjectId.Empty;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TAuthorization authorization,
        DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        authorization.CreationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TAuthorization authorization,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        if (properties is not { IsEmpty: false })
        {
            authorization.Properties = null;

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

        authorization.Properties = BsonDocument.Parse(Encoding.UTF8.GetString(stream.ToArray()));

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetScopesAsync(TAuthorization authorization,
        ImmutableArray<string> scopes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        authorization.Scopes = scopes is { IsDefaultOrEmpty: false } ? scopes : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TAuthorization authorization, string? status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        authorization.Status = status;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSubjectAsync(TAuthorization authorization, string? subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        authorization.Subject = subject;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetTypeAsync(TAuthorization authorization, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        authorization.Type = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        // Generate a new concurrency token and attach it
        // to the authorization before persisting the changes.
        var timestamp = authorization.ConcurrencyToken;
        authorization.ConcurrencyToken = Guid.NewGuid().ToString();

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TAuthorization>(Options.CurrentValue.AuthorizationsCollectionName);

        if ((await collection.ReplaceOneAsync(entity =>
            entity.Id == authorization.Id &&
            entity.ConcurrencyToken == timestamp, authorization, null as ReplaceOptions, cancellationToken)).MatchedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }
}
