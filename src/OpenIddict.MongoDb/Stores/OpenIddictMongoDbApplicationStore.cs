/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.MongoDb.Models;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.MongoDb;

/// <summary>
/// Provides methods allowing to manage the applications stored in a database.
/// </summary>
public class OpenIddictMongoDbApplicationStore : OpenIddictMongoDbApplicationStore<OpenIddictMongoDbApplication>
{
    public OpenIddictMongoDbApplicationStore(
        IOpenIddictMongoDbContext context,
        IOptionsMonitor<OpenIddictMongoDbOptions> options)
        : base(context, options)
    {
    }
}

/// <summary>
/// Provides methods allowing to manage the applications stored in a database.
/// </summary>
/// <typeparam name="TApplication">The type of the application entity.</typeparam>
public class OpenIddictMongoDbApplicationStore<
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TApplication> : IOpenIddictApplicationStore<TApplication>
    where TApplication : OpenIddictMongoDbApplication
{
    public OpenIddictMongoDbApplicationStore(
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
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        return await collection.CountDocumentsAsync(FilterDefinition<TApplication>.Empty, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<long> CountAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        return await query(collection.AsQueryable(), state).LongCountAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask CreateAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        await collection.InsertOneAsync(application, null, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask DeleteAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        if ((await collection.DeleteOneAsync(entity =>
            entity.Id == application.Id &&
            entity.ConcurrencyToken == application.ConcurrencyToken, cancellationToken)).DeletedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }

        // Delete the authorizations associated with the application.
        await database.GetCollection<OpenIddictMongoDbAuthorization>(Options.CurrentValue.AuthorizationsCollectionName)
            .DeleteManyAsync(authorization => authorization.ApplicationId == application.Id, cancellationToken);

        // Delete the tokens associated with the application.
        await database.GetCollection<OpenIddictMongoDbToken>(Options.CurrentValue.TokensCollectionName)
            .DeleteManyAsync(token => token.ApplicationId == application.Id, cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        return await collection.Find(application => application.ClientId == identifier).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual async ValueTask<TApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        return await collection.Find(application => application.Id ==
            ObjectId.Parse(identifier)).FirstOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(
        [StringSyntax(StringSyntaxAttribute.Uri)] string uri, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(uri);

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            await foreach (var application in collection.Find(application =>
                application.PostLogoutRedirectUris!.Contains(uri)).ToAsyncEnumerable().WithCancellation(cancellationToken))
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
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            await foreach (var application in collection.Find(application =>
                application.RedirectUris!.Contains(uri)).ToAsyncEnumerable().WithCancellation(cancellationToken))
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

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        return await query(collection.AsQueryable(), state).FirstOrDefaultAsync(cancellationToken);
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

        return new(application.Id.ToString());
    }

    /// <inheritdoc/>
    public virtual ValueTask<JsonWebKeySet?> GetJsonWebKeySetAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.JsonWebKeySet is BsonDocument set ? JsonWebKeySet.Create(set.ToJson()) : null);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetPermissionsAsync(
        TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.Permissions is { IsDefaultOrEmpty: false } permissions ? permissions : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(
        TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.PostLogoutRedirectUris is { IsDefaultOrEmpty: false } uris ? uris : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        if (application.Properties is null)
        {
            return new([]);
        }

        using var document = JsonDocument.Parse(application.Properties.ToJson());
        var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>(StringComparer.Ordinal);

        foreach (var property in document.RootElement.EnumerateObject())
        {
            builder[property.Name] = property.Value.Clone();
        }

        return new(builder.ToImmutable());
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(
        TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.RedirectUris is { IsDefaultOrEmpty: false } uris ? uris : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableArray<string>> GetRequirementsAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.Requirements is { IsDefaultOrEmpty: false } requirements ? requirements : []);
    }

    /// <inheritdoc/>
    public virtual ValueTask<ImmutableDictionary<string, string>> GetSettingsAsync(TApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        return new(application.Settings is { IsEmpty: false } settings ? settings : []);
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
    public virtual async IAsyncEnumerable<TApplication> ListAsync(
        int? count, int? offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        var query = (IQueryable<TApplication>) collection.AsQueryable().OrderBy(static application => application.Id);

        if (offset is not null)
        {
            query = query.Skip(offset.Value);
        }

        if (count is not null)
        {
            query = query.Take(count.Value);
        }

        await foreach (var application in ((IAsyncCursorSource<TApplication>) query).ToAsyncEnumerable().WithCancellation(cancellationToken))
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
            var database = await Context.GetDatabaseAsync(cancellationToken);
            var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

            await foreach (var element in query(collection.AsQueryable(), state).ToAsyncEnumerable().WithCancellation(cancellationToken))
            {
                yield return element;
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
    public virtual ValueTask SetClientIdAsync(TApplication application,
        string? identifier, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ClientId = identifier;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetClientSecretAsync(TApplication application,
        string? secret, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ClientSecret = secret;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetClientTypeAsync(TApplication application,
        string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ClientType = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetConsentTypeAsync(TApplication application,
        string? type, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.ConsentType = type;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetDisplayNameAsync(TApplication application,
        string? name, CancellationToken cancellationToken)
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

        application.DisplayNames = names is { Count: > 0 }
            ? names.ToImmutableDictionary(static pair => pair.Key.Name, static pair => pair.Value, StringComparer.Ordinal)
            : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetJsonWebKeySetAsync(TApplication application,
        JsonWebKeySet? set, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.JsonWebKeySet = set is not null ? BsonDocument.Parse(
            JsonSerializer.Serialize(set, OpenIddictSerializer.Default.JsonWebKeySet)) : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPermissionsAsync(TApplication application,
        ImmutableArray<string> permissions, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.Permissions = permissions is { IsDefaultOrEmpty: false } ? permissions : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPostLogoutRedirectUrisAsync(TApplication application,
        ImmutableArray<string> uris, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.PostLogoutRedirectUris = uris is { IsDefaultOrEmpty: false } ? uris : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetPropertiesAsync(TApplication application,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        if (properties is not { IsEmpty: false })
        {
            application.Properties = null;

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

        application.Properties = BsonDocument.Parse(Encoding.UTF8.GetString(stream.ToArray()));

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRedirectUrisAsync(TApplication application,
        ImmutableArray<string> uris, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.RedirectUris = uris is { IsDefaultOrEmpty: false } ? uris : null;

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc/>
    public virtual ValueTask SetRequirementsAsync(TApplication application,
        ImmutableArray<string> requirements, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);

        application.Requirements = requirements is { IsDefaultOrEmpty: false } ? requirements : null;

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

        // Generate a new concurrency token and attach it
        // to the application before persisting the changes.
        var timestamp = application.ConcurrencyToken;
        application.ConcurrencyToken = Guid.NewGuid().ToString();

        var database = await Context.GetDatabaseAsync(cancellationToken);
        var collection = database.GetCollection<TApplication>(Options.CurrentValue.ApplicationsCollectionName);

        if ((await collection.ReplaceOneAsync(entity =>
            entity.Id == application.Id &&
            entity.ConcurrencyToken == timestamp, application, null as ReplaceOptions, cancellationToken)).MatchedCount is 0)
        {
            throw new ConcurrencyException(SR.GetResourceString(SR.ID0239));
        }
    }
}
