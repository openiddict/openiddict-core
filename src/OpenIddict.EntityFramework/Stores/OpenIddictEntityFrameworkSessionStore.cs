/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Data;
using System.Data.Entity.Infrastructure;
using System.Diagnostics.CodeAnalysis;
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
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkSessionStore :
    OpenIddictEntityFrameworkSessionStore<OpenIddictEntityFrameworkSession,
                                          OpenIddictEntityFrameworkApplication,
                                          OpenIddictEntityFrameworkAuthorization,
                                          OpenIddictEntityFrameworkToken, string>
{
    public OpenIddictEntityFrameworkSessionStore(
        IMemoryCache cache,
        IOpenIddictEntityFrameworkContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
        : base(cache, context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the sessions stored in a database.
/// </summary>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkSessionStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictSessionStore<TSession>
    where TSession : OpenIddictEntityFrameworkSession<TKey, TApplication, TAuthorization, TToken>
    where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TSession, TToken>
    where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TSession, TToken>
    where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization, TSession>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkSessionStore(
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

        return await context.Set<TSession>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TSession>(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TSession>().Add(session);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var context = await Context.GetDbContextAsync(cancellationToken);

        // To prevent an SQL exception from being thrown if a new associated entity is
        // created after the existing entries have been listed, the following logic is
        // executed in a serializable transaction, that will lock the affected tables.
        using var transaction = CreateTransaction(context, IsolationLevel.Serializable);

        // Remove all the tokens associated with the session.
        var tokens = await
            (from token in context.Set<TToken>()
             where token.Authorization == null
             where token.Session!.Id!.Equals(session.Id)
             select token).ToListAsync(cancellationToken);

        foreach (var token in tokens)
        {
            context.Set<TToken>().Remove(token);
        }

        context.Set<TSession>().Remove(session);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the updated entities to prevents future calls from failing.
            context.Entry(session).State = EntityState.Unchanged;

            foreach (var token in tokens)
            {
                context.Entry(token).State = EntityState.Unchanged;
            }

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TSession> FindAsync(
        (string? Subject, string? LoginId, string? ApplicationId, string? AuthorizationId, string? Status) query,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TSession> sessions = context.Set<TSession>()
            .Include(static session => session.Application)
            .Include(static session => session.Authorization);

        if (!string.IsNullOrEmpty(query.Subject))
        {
            sessions = sessions.Where(session => session.Subject == query.Subject);
        }

        if (!string.IsNullOrEmpty(query.ApplicationId))
        {
            var key = ConvertIdentifierFromString(query.ApplicationId);
            sessions = sessions.Where(session => session.Application!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(query.AuthorizationId))
        {
            var key = ConvertIdentifierFromString(query.AuthorizationId);
            sessions = sessions.Where(session => session.Authorization!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(query.LoginId))
        {
            sessions = sessions.Where(session => session.LoginId == query.LoginId);
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            sessions = sessions.Where(session => session.Status == query.Status);
        }

        using var enumerator = ((IDbAsyncEnumerable<TSession>) sessions).GetAsyncEnumerator();

        while (await enumerator.MoveNextAsync(cancellationToken))
        {
            yield return enumerator.Current;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);
            var key = ConvertIdentifierFromString(identifier);

            var sessions = from session in context.Set<TSession>()
                               .Include(static session => session.Application)
                               .Include(static session => session.Authorization)
                           where session.Application!.Id!.Equals(key)
                           select session;

            using var enumerator = ((IDbAsyncEnumerable<TSession>) sessions).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
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
            var context = await Context.GetDbContextAsync(cancellationToken);
            var key = ConvertIdentifierFromString(identifier);

            var sessions = from session in context.Set<TSession>()
                               .Include(static session => session.Application)
                               .Include(static session => session.Authorization)
                           where session.Authorization!.Id!.Equals(key)
                           select session;

            using var enumerator = ((IDbAsyncEnumerable<TSession>) sessions).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TSession?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        return await context.Set<TSession>().FindAsync(cancellationToken, [key]);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TSession> FindByLoginIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TSession> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var sessions = from session in context.Set<TSession>()
                               .Include(static session => session.Application)
                               .Include(static session => session.Authorization)
                           where session.LoginId == identifier
                           select session;

            using var enumerator = ((IDbAsyncEnumerable<TSession>) sessions).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
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
            var context = await Context.GetDbContextAsync(cancellationToken);

            var sessions = from session in context.Set<TSession>()
                               .Include(static session => session.Application)
                               .Include(static session => session.Authorization)
                           where session.Subject == subject
                           select session;

            using var enumerator = ((IDbAsyncEnumerable<TSession>) sessions).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetApplicationIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        // If the application is not attached to the session, try to load it manually.
        if (session.Application is null)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var reference = context.Entry(session).Reference(static entry => entry.Application);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (session.Application is null)
        {
            return null;
        }

        return ConvertIdentifierToString(session.Application.Id);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TSession>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TSession>(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetAuthorizationIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        // If the application is not attached to the session, try to load it manually.
        if (session.Application is null)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            var reference = context.Entry(session).Reference(static entry => entry.Application);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (session.Application is null)
        {
            return null;
        }

        return ConvertIdentifierToString(session.Application.Id);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(session.CreationDate is DateTime date ? new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Utc)) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return new(ConvertIdentifierToString(session.Id));
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

        if (string.IsNullOrEmpty(session.Properties))
        {
            return new([]);
        }

        // Note: parsing the stringified properties is an expensive operation.
        // To mitigate that, the resulting object is stored in the memory cache.
        var key = string.Concat("7c674699-92a2-4607-a11b-a4d4edf9df46", "\x1e", session.Properties);
        var properties = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(session.Properties);
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
    public virtual async IAsyncEnumerable<TSession> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TSession> query = context.Set<TSession>().OrderBy(static session => session.Id!);

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        using var enumerator = ((IDbAsyncEnumerable<TSession>) query).GetAsyncEnumerator();

        while (await enumerator.MoveNextAsync(cancellationToken))
        {
            yield return enumerator.Current;
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
            var context = await Context.GetDbContextAsync(cancellationToken);

            using var enumerator = ((IDbAsyncEnumerable<TResult>) query(context.Set<TSession>(), state)).GetAsyncEnumerator();

            while (await enumerator.MoveNextAsync(cancellationToken))
            {
                yield return enumerator.Current;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        // Note: Entity Framework 6.x doesn't support set-based deletes, which prevents removing
        // entities in a single command without having to retrieve and materialize them first.
        // To work around this limitation, entities are manually listed and deleted using a batch logic.

        List<Exception>? exceptions = null;

        var result = 0L;

        // Note: to avoid sending too many queries, the maximum number of elements
        // that can be removed by a single call to PruneAsync() is deliberately limited.
        for (var index = 0; index < 1_000; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // To prevent concurrency exceptions from being thrown if an entry is modified
            // after it was retrieved from the database, the following logic is executed in
            // a repeatable read transaction, that will put a lock on the retrieved entries
            // and thus prevent them from being concurrently modified outside this block.
            using var transaction = CreateTransaction(context, IsolationLevel.RepeatableRead);

            // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
            // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
            // To work around this limitation, the threshold represented as a DateTimeOffset
            // instance is manually converted to a UTC DateTime instance outside the query.
            var date = threshold.UtcDateTime;

            var sessions =
                await (from session in context.Set<TSession>().Include(static session => session.Tokens)
                       where session.CreationDate < date
                       where session.Status != Statuses.Valid
                       where !session.Tokens.Any()
                       orderby session.Id
                       select session).Take(1_000).ToListAsync(cancellationToken);

            if (sessions.Count is 0)
            {
                break;
            }

            // Note: new tokens may be attached after the sessions were retrieved
            // from the database since the transaction level is deliberately limited to
            // repeatable read instead of serializable for performance reasons). In this
            // case, the operation will fail, which is considered an acceptable risk.
            context.Set<TSession>().RemoveRange(sessions);

            try
            {
                await context.SaveChangesAsync(cancellationToken);
                transaction?.Commit();
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                exceptions ??= new List<Exception>(capacity: 1);
                exceptions.Add(exception);

                continue;
            }

            result += sessions.Count;
        }

        if (exceptions is { Count: > 0 })
        {
            throw new AggregateException(exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetApplicationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (!string.IsNullOrEmpty(identifier))
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            session.Application = await context.Set<TApplication>().FindAsync(
                cancellationToken, ConvertIdentifierFromString(identifier))
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0244));
        }

        else
        {
            // If the application is not attached to the session, try to load it manually.
            if (session.Application is null)
            {
                var context = await Context.GetDbContextAsync(cancellationToken);

                var reference = context.Entry(session).Reference(static entry => entry.Application);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            session.Application = null;
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetAuthorizationIdAsync(TSession session, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        if (!string.IsNullOrEmpty(identifier))
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            session.Authorization = await context.Set<TAuthorization>().FindAsync(
                cancellationToken, ConvertIdentifierFromString(identifier))
                ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0244));
        }

        else
        {
            // If the authorization is not attached to the session, try to load it manually.
            if (session.Authorization is null)
            {
                var context = await Context.GetDbContextAsync(cancellationToken);

                var reference = context.Entry(session).Reference(static entry => entry.Authorization);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            session.Authorization = null;
        }
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

        session.Properties = Encoding.UTF8.GetString(stream.ToArray());

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

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TSession>().Attach(session);

        // Generate a new concurrency token and attach it
        // to the session before persisting the changes.
        session.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Entry(session).State = EntityState.Modified;

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the updated entities to prevents future calls from failing.
            context.Entry(session).State = EntityState.Unchanged;

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

    /// <summary>
    /// Tries to create a new <see cref="DbContextTransaction"/> with the specified <paramref name="level"/>.
    /// </summary>
    /// <param name="context">The Entity Framework context.</param>
    /// <param name="level">The desired level of isolation.</param>
    /// <returns>The <see cref="DbContextTransaction"/> if it could be created, <see langword="null"/> otherwise.</returns>
    protected virtual DbContextTransaction? CreateTransaction(DbContext context, IsolationLevel level)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            return context.Database.BeginTransaction(level);
        }

        catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
        {
            return null;
        }
    }
}
