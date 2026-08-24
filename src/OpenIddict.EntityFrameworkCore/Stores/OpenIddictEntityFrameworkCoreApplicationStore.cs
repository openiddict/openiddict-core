/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Data;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.EntityFrameworkCore;

/// <summary>
/// Provides methods allowing to manage the applications stored in a database.
/// </summary>
public class OpenIddictEntityFrameworkCoreApplicationStore :
    OpenIddictEntityFrameworkCoreApplicationStore<OpenIddictEntityFrameworkCoreApplication,
                                                  OpenIddictEntityFrameworkCoreAuthorization,
                                                  OpenIddictEntityFrameworkCoreSession,
                                                  OpenIddictEntityFrameworkCoreToken, string>
{
    public OpenIddictEntityFrameworkCoreApplicationStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the applications stored in a database.
/// </summary>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreApplicationStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> :
    OpenIddictEntityFrameworkCoreApplicationStore<OpenIddictEntityFrameworkCoreApplication<TKey>,
                                                  OpenIddictEntityFrameworkCoreAuthorization<TKey>,
                                                  OpenIddictEntityFrameworkCoreSession<TKey>,
                                                  OpenIddictEntityFrameworkCoreToken<TKey>, TKey>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreApplicationStore(
        IOpenIddictEntityFrameworkCoreContext context,
        IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the applications stored in a database.
/// </summary>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
/// <typeparam name="TAuthorization">The type of the authorization entity.</typeparam>
/// <typeparam name="TSession">The type of the session entity.</typeparam>
/// <typeparam name="TToken">The type of the token entity.</typeparam>
/// <typeparam name="TKey">The type of the entity primary keys.</typeparam>
public class OpenIddictEntityFrameworkCoreApplicationStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TAuthorization,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TSession,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TToken,
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TKey> : IOpenIddictApplicationStore<TApplication>
    where TApplication : OpenIddictEntityFrameworkCoreApplication<TKey, TAuthorization, TSession, TToken>
    where TAuthorization : OpenIddictEntityFrameworkCoreAuthorization<TKey, TApplication, TSession, TToken>
    where TToken : OpenIddictEntityFrameworkCoreToken<TKey, TApplication, TAuthorization, TSession>
    where TSession : OpenIddictEntityFrameworkCoreSession<TKey, TApplication, TAuthorization, TToken>
    where TKey : notnull, IEquatable<TKey>
{
    public OpenIddictEntityFrameworkCoreApplicationStore(
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

        return await context.Set<TApplication>().LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TApplication>(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var context = await Context.GetDbContextAsync(cancellationToken);
        context.Add(application);

        await context.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var context = await Context.GetDbContextAsync(cancellationToken);

        if (!Options.CurrentValue.DisableBulkOperations)
        {
            var strategy = context.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                // To prevent an SQL exception from being thrown if a new associated entity is
                // created after the existing entries have been listed, the following logic is
                // executed in a serializable transaction, that will lock the affected tables.
                await using var transaction = await CreateTransactionAsync(context,
                    IsolationLevel.Serializable, cancellationToken);

                // Remove all the tokens associated with the application.
                await (from token in context.Set<TToken>()
                       where token.Application!.Id!.Equals(application.Id)
                       select token).ExecuteDeleteAsync(cancellationToken);

                // Remove all the authorizations associated with the application.
                await (from authorization in context.Set<TAuthorization>()
                       where authorization.Application!.Id!.Equals(application.Id)
                       select authorization).ExecuteDeleteAsync(cancellationToken);

                // Remove all the sessions associated with the application.
                await (from session in context.Set<TSession>()
                       where session.Application!.Id!.Equals(application.Id)
                       select session).ExecuteDeleteAsync(cancellationToken);

                // Note: calling DbContext.SaveChangesAsync() is not necessary
                // with bulk delete operations as they are executed immediately.

                context.Remove(application);

                try
                {
                    await context.SaveChangesAsync(cancellationToken);

                    if (transaction is not null)
                    {
                        await transaction.CommitAsync(cancellationToken);
                    }
                }

                catch (DbUpdateConcurrencyException exception)
                {
                    // Reset the state of the updated entities to prevents future calls from failing.
                    context.Entry(application).State = EntityState.Unchanged;

                    throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
                }
            });
        }

        else
        {
            var strategy = context.Database.CreateExecutionStrategy();
            await strategy.ExecuteAsync(async () =>
            {
                // To prevent an SQL exception from being thrown if a new associated entity is
                // created after the existing entries have been listed, the following logic is
                // executed in a serializable transaction, that will lock the affected tables.
                await using var transaction = await CreateTransactionAsync(context,
                    IsolationLevel.Serializable, cancellationToken);

                // Remove all the authorizations associated with the application and
                // the tokens attached to these implicit or explicit authorizations.
                var authorizations = await (
                    from authorization in context.Set<TAuthorization>()
                        .Include(static authorization => authorization.Tokens)
                        .AsTracking()
                    where authorization.Application!.Id!.Equals(application.Id)
                    select authorization).ToListAsync(cancellationToken);

                foreach (var authorization in authorizations)
                {
                    foreach (var token in authorization.Tokens)
                    {
                        context.Remove(token);
                    }

                    context.Remove(authorization);
                }

                // Remove all the sessions associated with the application, the authorizations associated
                // with the session and the tokens attached to these authorizations and sessions.
                var sessions = await
                    (from session in context.Set<TSession>()
                        .Include(static session => session.Authorization!.Tokens)
                        .Include(static session => session.Tokens)
                        .AsTracking()
                     where session.Application!.Id!.Equals(application.Id)
                     select session).ToListAsync(cancellationToken);

                foreach (var session in sessions)
                {
                    if (session.Authorization is not null)
                    {
                        foreach (var token in session.Authorization.Tokens)
                        {
                            context.Remove(token);
                        }

                        context.Remove(session.Authorization);
                    }

                    foreach (var token in session.Tokens)
                    {
                        context.Remove(token);
                    }

                    context.Remove(session);
                }

                // Remove all the tokens associated with the application.
                var tokens = await (
                    from token in context.Set<TToken>().AsTracking()
                    where token.Authorization == null
                    where token.Application!.Id!.Equals(application.Id)
                    select token).ToListAsync(cancellationToken);

                foreach (var token in tokens)
                {
                    context.Remove(token);
                }

                context.Remove(application);

                try
                {
                    await context.SaveChangesAsync(cancellationToken);

                    if (transaction is not null)
                    {
                        await transaction.CommitAsync(cancellationToken);
                    }
                }

                catch (DbUpdateConcurrencyException exception)
                {
                    // Reset the state of the updated entities to prevents future calls from failing.
                    context.Entry(application).State = EntityState.Unchanged;

                    foreach (var authorization in authorizations)
                    {
                        context.Entry(authorization).State = EntityState.Unchanged;

                        foreach (var token in authorization.Tokens)
                        {
                            context.Entry(token).State = EntityState.Unchanged;
                        }
                    }

                    foreach (var session in sessions)
                    {
                        context.Entry(session).State = EntityState.Unchanged;

                        if (session.Authorization is not null)
                        {
                            context.Entry(session.Authorization).State = EntityState.Unchanged;

                            foreach (var token in session.Authorization.Tokens)
                            {
                                context.Entry(token).State = EntityState.Unchanged;
                            }
                        }

                        foreach (var token in session.Tokens)
                        {
                            context.Entry(token).State = EntityState.Unchanged;
                        }
                    }

                    foreach (var token in tokens)
                    {
                        context.Entry(token).State = EntityState.Unchanged;
                    }

                    throw new ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
                }
            });
        }
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return GetTrackedEntity() is TApplication application ? application : await QueryAsync();

        TApplication? GetTrackedEntity() =>
            (from entry in context.ChangeTracker.Entries<TApplication>()
             where string.Equals(entry.Entity.ClientId, identifier, StringComparison.Ordinal)
             select entry.Entity).FirstOrDefault();

        Task<TApplication?> QueryAsync() =>
            (from application in context.Set<TApplication>().AsTracking()
             where application.ClientId == identifier
             select application).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var context = await Context.GetDbContextAsync(cancellationToken);
        var key = ConvertIdentifierFromString(identifier);

        return await context.Set<TApplication>().FindAsync([key], cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(
        [StringSyntax(StringSyntaxAttribute.Uri)] string uri, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var application in
                (from application in context.Set<TApplication>().AsTracking()
                 where application.PostLogoutRedirectUris!.Contains(uri)
                 select application).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return application;
            }
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TApplication> FindByRedirectUriAsync(
        [StringSyntax(StringSyntaxAttribute.Uri)] string uri, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var application in
                (from application in context.Set<TApplication>().AsTracking()
                 where application.RedirectUris!.Contains(uri)
                 select application).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return application;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetApplicationTypeAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.ApplicationType);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var context = await Context.GetDbContextAsync(cancellationToken);

        return await query(context.Set<TApplication>().AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetClientIdAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.ClientId);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetClientSecretAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.ClientSecret);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetClientTypeAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.ClientType);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetConsentTypeAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.ConsentType);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.DisplayName);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.DisplayNames is { Count: > 0 } names
            ? names.ToImmutableDictionary(static pair => CultureInfo.GetCultureInfo(pair.Key), static pair => pair.Value)
            : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<string?> GetIdAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(ConvertIdentifierToString(application.Id));
    }

    /// <inheritdoc/>
    public virtual ValueTask<JsonWebKeySet?> GetJsonWebKeySetAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.JsonWebKeySet);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetPermissionsAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.Permissions is { Length: > 0 } permissions ? [.. permissions] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.PostLogoutRedirectUris is { Length: > 0 } uris ? [.. uris] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.Properties is { Count: > 0 } properties ? [.. properties] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.RedirectUris is { Length: > 0 } uris ? [.. uris] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetRequirementsAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.Requirements is { Length: > 0 } requirements ? [.. requirements] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, string>> GetSettingsAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.Settings is { Count: > 0 } settings ? [.. settings] : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<TApplication> InstantiateAsync(CancellationToken cancellationToken)
    {
        try
        {
            return new(Activator.CreateInstance<TApplication>());
        }

        catch (MemberAccessException exception)
        {
            return new(Task.FromException<TApplication>(
                new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
        }
    }

    /// <inheritdoc/>
    public virtual async IAsyncEnumerable<TApplication> ListAsync(int? count, int? offset,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var context = await Context.GetDbContextAsync(cancellationToken);

        var query = context.Set<TApplication>().OrderBy(static application => application.Id!).AsTracking();

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var application in query.AsAsyncEnumerable().WithCancellation(cancellationToken))
        {
            yield return application;
        }
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TResult> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var context = await Context.GetDbContextAsync(cancellationToken);

            await foreach (var application in query(context.Set<TApplication>().AsTracking(), state).AsAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return application;
            }
        }
    }

    /// <inheritdoc/>
    public virtual ValueTask SetApplicationTypeAsync(TApplication application,
        string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ApplicationType = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetClientIdAsync(TApplication application, string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ClientId = identifier;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetClientSecretAsync(TApplication application, string? secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ClientSecret = secret;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetClientTypeAsync(TApplication application, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ClientType = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetConsentTypeAsync(TApplication application, string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ConsentType = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDisplayNameAsync(TApplication application, string? name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.DisplayName = name;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDisplayNamesAsync(TApplication application,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.DisplayNames = names is { IsEmpty: false }
            ? names.ToImmutableDictionary(static pair => pair.Key.Name, static pair => pair.Value, StringComparer.Ordinal)
            : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetJsonWebKeySetAsync(TApplication application, JsonWebKeySet? set, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.JsonWebKeySet = set;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPermissionsAsync(TApplication application, ImmutableArray<string> permissions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.Permissions = permissions is { IsDefaultOrEmpty: false } ? [.. permissions] : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPostLogoutRedirectUrisAsync(TApplication application,
        ImmutableArray<string> uris, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.PostLogoutRedirectUris = uris is { IsDefaultOrEmpty: false } ? [.. uris] : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TApplication application,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.Properties = properties;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRedirectUrisAsync(TApplication application,
        ImmutableArray<string> uris, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.RedirectUris = uris is { IsDefaultOrEmpty: false } ? [.. uris] : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRequirementsAsync(TApplication application, ImmutableArray<string> requirements, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.Requirements = requirements is { IsDefaultOrEmpty: false } ? [.. requirements] : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetSettingsAsync(TApplication application,
        ImmutableDictionary<string, string> settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.Settings = settings is { IsEmpty: false } ? settings : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual async ValueTask UpdateAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var context = await Context.GetDbContextAsync(cancellationToken);

        context.Attach(application);

        // Generate a new concurrency token and attach it
        // to the application before persisting the changes.
        application.ConcurrencyToken = Guid.NewGuid().ToString();

        context.Update(application);

        try
        {
            await context.SaveChangesAsync(cancellationToken);
        }

        catch (DbUpdateConcurrencyException exception)
        {
            // Reset the state of the updated entities to prevents future calls from failing.
            context.Entry(application).State = EntityState.Unchanged;

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

        var converter = TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));

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

        var converter = TypeDescriptor.GetConverterFromRegisteredType(typeof(TKey));

        return converter.ConvertToInvariantString(identifier);
    }

    /// <summary>
    /// Tries to create a new <see cref="IDbContextTransaction"/> with the specified <paramref name="level"/>.
    /// </summary>
    /// <param name="context">The Entity Framework Core context.</param>
    /// <param name="level">The desired level of isolation.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The <see cref="IDbContextTransaction"/> if it could be created, <see langword="null"/> otherwise.</returns>
    protected virtual async ValueTask<IDbContextTransaction?> CreateTransactionAsync(
        DbContext context, IsolationLevel level, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        // Note: transactions that specify an explicit isolation level are only supported by
        // relational providers and trying to use them with a different provider results in
        // an invalid operation exception being thrown at runtime. To prevent that, a manual
        // check is made to ensure the underlying transaction manager is relational.
        var manager = context.GetService<IDbContextTransactionManager>();
        if (manager is IRelationalTransactionManager)
        {
            try
            {
                return await context.Database.BeginTransactionAsync(level, cancellationToken);
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                return null;
            }
        }

        return null;
    }
}
