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
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
public class OpenIddictMongoDbSessionStore : OpenIddictMongoDbSessionStore<OpenIddictMongoDbSession>
{
    public OpenIddictMongoDbSessionStore(
        IOpenIddictMongoDbContext context,
        IOptionsMonitor<OpenIddictMongoDbOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
public class OpenIddictMongoDbSessionStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession> : IOpenIddictSessionStore<TSession>
    where TSession : OpenIddictMongoDbSession
{
    public OpenIddictMongoDbSessionStore(
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
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        return await collection.CountDocumentsAsync(FilterDefinition<TSession>.Empty, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        return await query(collection.AsQueryable(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        await collection.InsertOneAsync(session, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        if ((await collection.DeleteOneAsync(entity =>
            entity.Id == session.Id &&
            entity.ConcurrencyToken == session.ConcurrencyToken, cancellationToken)).DeletedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TSession> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? Status) query,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        IQueryable<TSession> sessions = collection.AsQueryable();

        if (!string.IsNullOrEmpty(query.Subject))
        {
            sessions = sessions.Where(session => session.Subject == query.Subject);
        }

        if (!string.IsNullOrEmpty(query.ApplicationId))
        {
            sessions = sessions.Where(session => session.ApplicationId == ObjectId.Parse(query.ApplicationId));
        }

        if (!string.IsNullOrEmpty(query.LoginId))
        {
            sessions = sessions.Where(session => session.LoginId == query.LoginId);
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            sessions = sessions.Where(session => session.Status == query.Status);
        }

        await foreach (var session in sessions.ToAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return session;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

            await foreach (var session in collection.Find(session =>
                session.ApplicationId == ObjectId.Parse(identifier)).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

            await foreach (var session in collection.Find(session =>
                session.AuthorizationId == ObjectId.Parse(identifier)).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TSession?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        return await collection.Find(session => session.Id == ObjectId.Parse(identifier)).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByLoginIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

            await foreach (var session in collection.Find(session => session.LoginId == identifier).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(subject);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

            await foreach (var session in collection.Find(session => session.Subject == subject).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return session;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetApplicationIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.ApplicationId != ObjectId.Empty ? session.ApplicationId.ToString() : null);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        return await query(collection.AsQueryable(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetAuthorizationIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.AuthorizationId != ObjectId.Empty ? session.AuthorizationId.ToString() : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.CreationDate is DateTime date ? DateTime.SpecifyKind(date, DateTimeKind.Utc) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.Id.ToString());
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetLoginIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.LoginId);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (session.Properties is null)
        {
            return new(ImmutableDictionary.Create<string, JsonElement>());
        }

        using var document = JsonDocument.Parse(session.Properties.ToJson());
        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();

        foreach (var property in document.RootElement.EnumerateObject())
        {
            builder[property.Name] = property.Value.Clone();
        }

        return new(builder.ToImmutable());
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.Status);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetSubjectAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.Subject);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TSession> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TSession>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TSession>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TSession> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        var query = (IQueryable<TSession>) collection.AsQueryable().OrderBy(session => session.Id);

        if (offset.HasValue)
        {
            query = query.Skip(offset.Value);
        }

        if (count.HasValue)
        {
            query = query.Take(count.Value);
        }

        await foreach (var session in ((IAsyncCursorSource<TSession>) query).ToAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return session;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

            await foreach (var element in query(collection.AsQueryable(), state).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return element;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetApplicationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.ApplicationId = !string.IsNullOrEmpty(identifier) ? ObjectId.Parse(identifier) : ObjectId.Empty;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetAuthorizationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.AuthorizationId = !string.IsNullOrEmpty(identifier) ? ObjectId.Parse(identifier) : ObjectId.Empty;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TSession session, DateTimeOffset? date, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.CreationDate = date?.UtcDateTime;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TSession session,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (properties is not { IsEmpty: false })
        {
            session.Properties = null;

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

        session.Properties = BsonDocument.Parse(Encoding.UTF8.GetString(stream.ToArray()));

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetLoginIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.LoginId = identifier;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TSession session, string? status, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.Status = status;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSubjectAsync(TSession session, string? subject, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        session.Subject = subject;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        // Generate a new concurrency token and attach it
        // to the session before persisting the changes.
        var timestamp = session.ConcurrencyToken;
        session.ConcurrencyToken = Guid.NewGuid().ToString();

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TSession>(Options.CurrentValue.SessionsCollectionName);

        if ((await collection.ReplaceOneAsync(entity =>
            entity.Id == session.Id &&
            entity.ConcurrencyToken == timestamp, session, null as ReplaceOptions, cancellationToken)).MatchedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }
}
