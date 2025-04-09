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
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFramework;

/// <summary>
/// Provides methods allowing to manage the authorizations stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkAuthorizationStore :
    OpenIddictEntityFrameworkAuthorizationStore<OpenIddictEntityFrameworkAuthorization,
                                                OpenIddictEntityFrameworkApplication,
                                                OpenIddictEntityFrameworkToken, string>
{
    public OpenIddictEntityFrameworkAuthorizationStore(
        IMemoryCache cache,
        IOpenIddictEntityFrameworkContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkOptions> options)
        : base(cache, context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the authorizations stored in a database.
/// </summary>
/// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
/// <typeparam name="TApplication">The type of the Application entity.</typeparam>
/// <typeparam name="TToken">The type of the Token entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkAuthorizationStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictAuthorizationStore<TAuthorization>
    where TAuthorization : OpenIddictEntityFrameworkAuthorization<TKey, TApplication, TToken>
    where TApplication : OpenIddictEntityFrameworkApplication<TKey, TAuthorization, TToken>
    where TToken : OpenIddictEntityFrameworkToken<TKey, TApplication, TAuthorization>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkAuthorizationStore(
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

        return await context.Set<TAuthorization>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TResult>(Func<IQueryable<TAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TAuthorization>()).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TAuthorization>().Add(authorization);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        Task<List<TToken>> ListTokensAsync()
            => (from token in context.Set<TToken>()
                where token.Authorization!.Id!.Equals(authorization.Id)
                select token).ToListAsync(cancellationToken);

        // To prevent an SQL exception from being thrown if a new associated entity is
        // created after the existing entries have been listed, the following logic is
        // executed in a serializable transaction, that will lock the affected tables.
        using var transaction = context.CreateTransaction(IsolationLevel.Serializable);

        // Remove all the tokens associated with the authorization.
        var tokens = await ListTokensAsync();
        foreach (var token in tokens)
        {
            context.Set<TToken>().Remove(token);
        }

        context.Set<TAuthorization>().Remove(authorization);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
            transaction?.Commit();
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            context.Entry(authorization).State = EntityState.Unchanged;

            foreach (var token in tokens)
            {
                context.Entry(token).State = EntityState.Unchanged;
            }

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0241), exception);
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TAuthorization> FindAsync(
        string? subject, string? client,
        string? status, string? type,
        ImmutableArray<string>? scopes, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TAuthorization> query = context.Set<TAuthorization>().Include(authorization => authorization.Application);

        if (!string.IsNullOrEmpty(subject))
        {
            query = query.Where(authorization => authorization.Subject == subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            var key = ConvertIdentifierFromString(client);

            query = query.Where(authorization => authorization.Application!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(status))
        {
            query = query.Where(authorization => authorization.Status == status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            query = query.Where(authorization => authorization.Type == type);
        }

        await foreach (var authorization in query.AsAsyncEnumerable(cancellationToken))
        {
            if (scopes is null || (await GetScopesAsync(authorization, cancellationToken))
                .ToHashSet(StringComparer.Ordinal)
                .IsSupersetOf(scopes))
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TAuthorization> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);
            var key = ConvertIdentifierFromString(identifier);

            await foreach (var authorization in
                (from authorization in context.Set<TAuthorization>().Include(authorization => authorization.Application)
                 where authorization.Application!.Id!.Equals(key)
                 select authorization).AsAsyncEnumerable(cancellationToken))
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TAuthorization?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        return GetTrackedEntity() is TAuthorization authorization ? authorization : await QueryAsync();

        TAuthorization? GetTrackedEntity() =>
            (from entry in context.ChangeTracker.Entries<TAuthorization>()
             where entry.Entity.Id is TKey identifier && identifier.Equals(key)
             select entry.Entity).FirstOrDefault();

        Task<TAuthorization?> QueryAsync() =>
            (from authorization in context.Set<TAuthorization>().Include(authorization => authorization.Application)
             where authorization.Id!.Equals(key)
             select authorization).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TAuthorization> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var authorization in
                (from authorization in context.Set<TAuthorization>().Include(authorization => authorization.Application)
                 where authorization.Subject == subject
                 select authorization).AsAsyncEnumerable(cancellationToken))
            {
                yield return authorization;
            }
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<string?> GetApplicationIdAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        // If the application is not attached to the authorization, try to load it manually.
        if (authorization.Application is null)
        {
            var reference = context.Entry(authorization).Reference(entry => entry.Application);
            if (reference.EntityEntry.State is EntityState.Detached)
            {
                return null;
            }

            await reference.LoadAsync(cancellationToken);
        }

        if (authorization.Application is null)
        {
            return null;
        }

        return ConvertIdentifierToString(authorization.Application.Id);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(
            context.Set<TAuthorization>().Include(authorization => authorization.Application), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (authorization.CreationDate is null)
        {
            return new(result: null);
        }

        return new(DateTime.SpecifyKind(authorization.CreationDate.Value, DateTimeKind.Utc));
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return new(ConvertIdentifierToString(authorization.Id));
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (string.IsNullOrEmpty(authorization.Properties))
        {
            return new(ImmutableDictionary.Create<string, JsonElement>());
        }

        // Note: parsing the stringified properties is an expensive operation.
        // To mitigate that, the resulting object is stored in the memory cache.
        var key = string.Concat("68056e1a-dbcf-412b-9a6a-d791c7dbe726", "\x1e", authorization.Properties);
        var properties = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(authorization.Properties);
            var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();

            foreach (var property in document.RootElement.EnumerateObject())
            {
                builder[property.Name] = property.Value.Clone();
            }

            return builder.ToImmutable();
        })!;

        return new(properties);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetScopesAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (string.IsNullOrEmpty(authorization.Scopes))
        {
            return new([]);
        }

        // Note: parsing the stringified scopes is an expensive operation.
        // To mitigate that, the resulting array is stored in the memory cache.
        var key = string.Concat("2ba4ab0f-e2ec-4d48-b3bd-28e2bb660c75", "\x1e", authorization.Scopes);
        var scopes = Cache.GetOrCreate(key, entry =>
        {
            entry.SetPriority(CacheItemPriority.High)
                 .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            using var document = JsonDocument.Parse(authorization.Scopes);
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

        return new(scopes);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetStatusAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return new(authorization.Status);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetSubjectAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        return new(authorization.Subject);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetTypeAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

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
                new InvalidOperationException(SR.GetResourceString(SR.ID0242), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TAuthorization> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TAuthorization> query = context.Set<TAuthorization>()
                                                  .Include(authorization => authorization.Application)
                                                  .OrderBy(authorization => authorization.Id!);

        if (offset.HasValue)
        {
            query = query.Skip(offset.Value);
        }

        if (count.HasValue)
        {
            query = query.Take(count.Value);
        }

        await foreach (var authorization in query.AsAsyncEnumerable(cancellationToken))
        {
            yield return authorization;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TAuthorization>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var authorization in query(context
                .Set<TAuthorization>()
                .Include(authorization => authorization.Application), state).AsAsyncEnumerable(cancellationToken))
            {
                yield return authorization;
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
            using var transaction = context.CreateTransaction(IsolationLevel.RepeatableRead);

            // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
            // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
            // To work around this limitation, the threshold represented as a DateTimeOffset
            // instance is manually converted to a UTC DateTime instance outside the query.
            var date = threshold.UtcDateTime;

            var authorizations =
                await (from authorization in context.Set<TAuthorization>().Include(authorization => authorization.Tokens)
                       where authorization.CreationDate < date
                       where authorization.Status != Statuses.Valid || authorization.Type == AuthorizationTypes.AdHoc
                       where !authorization.Tokens.Any()
                       orderby authorization.Id
                       select authorization).Take(1_000).ToListAsync(cancellationToken);

            if (authorizations.Count is 0)
            {
                break;
            }

            // Note: new tokens may be attached after the authorizations were retrieved
            // from the database since the transaction level is deliberately limited to
            // repeatable read instead of serializable for performance reasons). In this
            // case, the operation will fail, which is considered an acceptable risk.
            context.Set<TAuthorization>().RemoveRange(authorizations);

            try
            {
                await context.SaveChangesAsync(cancellationToken);
                transaction?.Commit();
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result += authorizations.Count;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0243), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeAsync(string? subject, string? client, string? status, string? type, CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        IQueryable<TAuthorization> query = context.Set<TAuthorization>().Include(authorization => authorization.Application);

        if (!string.IsNullOrEmpty(subject))
        {
            query = query.Where(authorization => authorization.Subject == subject);
        }

        if (!string.IsNullOrEmpty(client))
        {
            var key = ConvertIdentifierFromString(client);

            query = query.Where(authorization => authorization.Application!.Id!.Equals(key));
        }

        if (!string.IsNullOrEmpty(status))
        {
            query = query.Where(authorization => authorization.Status == status);
        }

        if (!string.IsNullOrEmpty(type))
        {
            query = query.Where(authorization => authorization.Type == type);
        }

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var authorization in await query.ToListAsync(cancellationToken))
        {
            authorization.Status = Statuses.Revoked;

            try
            {
                await context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                context.Entry(authorization).State = EntityState.Unchanged;

                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var authorization in await (from authorization in context.Set<TAuthorization>()
                                                                          .Include(authorization => authorization.Application)
                                             where authorization.Application!.Id!.Equals(key)
                                             select authorization).ToListAsync(cancellationToken))
        {
            authorization.Status = Statuses.Revoked;

            try
            {
                await context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                context.Entry(authorization).State = EntityState.Unchanged;

                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> RevokeBySubjectAsync(string subject, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(subject))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(subject));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        List<Exception>? exceptions = null;

        var result = 0L;

        foreach (var authorization in await (from authorization in context.Set<TAuthorization>()
                                                                          .Include(authorization => authorization.Application)
                                             where authorization.Subject == subject
                                             select authorization).ToListAsync(cancellationToken))
        {
            authorization.Status = Statuses.Revoked;

            try
            {
                await context.SaveChangesAsync(cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                context.Entry(authorization).State = EntityState.Unchanged;

                exceptions ??= [];
                exceptions.Add(exception);

                continue;
            }

            result++;
        }

        if (exceptions is not null)
        {
            throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
        }

        return result;
    }

    /// <inheritdoc/>
    public virtual async ValueTask SetApplicationIdAsync(TAuthorization authorization,
        string? identifier, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        if (!string.IsNullOrEmpty(identifier))
        {
            authorization.Application = await context.Set<TApplication>().FindAsync(
                cancellationToken, ConvertIdentifierFromString(identifier)) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0244));
        }

        else
        {
            // If the application is not attached to the authorization, try to load it manually.
            if (authorization.Application is null)
            {
                var reference = context.Entry(authorization).Reference(entry => entry.Application);
                if (reference.EntityEntry.State is EntityState.Detached)
                {
                    return;
                }

                await reference.LoadAsync(cancellationToken);
            }

            authorization.Application = null;
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetCreationDateAsync(TAuthorization authorization,
        DateTimeOffset? date, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        authorization.CreationDate = date?.UtcDateTime;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TAuthorization authorization,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (properties is not { Count: > 0 })
        {
            authorization.Properties = null;

            return default;
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

        authorization.Properties = Encoding.UTF8.GetString(stream.ToArray());

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetScopesAsync(TAuthorization authorization,
        ImmutableArray<string> scopes, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        if (scopes.IsDefaultOrEmpty)
        {
            authorization.Scopes = null;

            return default;
        }

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = false
        });

        writer.WriteStartArray();

        foreach (var scope in scopes)
        {
            writer.WriteStringValue(scope);
        }

        writer.WriteEndArray();
        writer.Flush();

        authorization.Scopes = Encoding.UTF8.GetString(stream.ToArray());

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetStatusAsync(TAuthorization authorization, string? status, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        authorization.Status = status;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSubjectAsync(TAuthorization authorization, string? subject, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        authorization.Subject = subject;

        return default;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetTypeAsync(TAuthorization authorization, string? type, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        authorization.Type = type;

        return default;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TAuthorization authorization, CancellationToken cancellationToken)
    {
        if (authorization is null)
        {
            throw new ArgumentNullException(nameof(authorization));
        }

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Set<TAuthorization>().Attach(authorization);

        // Generate a new concurrency token and attach it
        // to the authorization before persisting the changes.
        authorization.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Entry(authorization).State = EntityState.Modified;

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
            context.Entry(authorization).State = EntityState.Unchanged;

            throw new ConcurrencyException(SR.GetResourceString(SR.ID0241), exception);
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
            var converter =
#if SUPPORTS_TYPE_DESCRIPTOR_TYPE_REGISTRATION
                TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));
#else
                TypeDescriptor.GetConverter(typeof(TKey));
#endif

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
            var converter =
#if SUPPORTS_TYPE_DESCRIPTOR_TYPE_REGISTRATION
                TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));
#else
                TypeDescriptor.GetConverter(typeof(TKey));
#endif

            return converter.ConvertToInvariantString(identifier);
        }
    }
}
