/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Binary;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;
using ValidationException = OpenIddict.Abstractions.OpenIddictExceptions.ValidationException;

#if !SUPPORTS_KEY_DERIVATION_WITH_SPECIFIED_HASH_ALGORITHM
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
#endif

#if !SUPPORTS_TIME_CONSTANT_COMPARISONS
using Org.BouncyCastle.Utilities;
#endif

namespace OpenIddict.Core;

/// <summary>
/// Provides methods allowing to manage the applications stored in the store.
/// </summary>
/// <remarks>
/// Applications that do not want to depend on a specific entity type can use the non-generic
/// <see cref="IOpenIddictApplicationManager"/> instead, for which the actual entity type
/// is resolved at runtime based on the default entity type registered in the core options.
/// </remarks>
/// <typeparam name="TApplication">The type of the Application entity.</typeparam>
public class OpenIddictApplicationManager<TApplication> : IOpenIddictApplicationManager where TApplication : class
{
    public OpenIddictApplicationManager(
        IOpenIddictApplicationCache<TApplication> cache,
        ILogger<OpenIddictApplicationManager<TApplication>> logger,
        IOptionsMonitor<OpenIddictCoreOptions> options,
        IOpenIddictApplicationStoreResolver resolver)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        Store = (resolver ?? throw new ArgumentNullException(nameof(resolver))).Get<TApplication>();
    }

    /// <summary>
    /// Gets the cache associated with the current manager.
    /// </summary>
    protected IOpenIddictApplicationCache<TApplication> Cache { get; }

    /// <summary>
    /// Gets the logger associated with the current manager.
    /// </summary>
    protected ILogger Logger { get; }

    /// <summary>
    /// Gets the options associated with the current manager.
    /// </summary>
    protected IOptionsMonitor<OpenIddictCoreOptions> Options { get; }

    /// <summary>
    /// Gets the store associated with the current manager.
    /// </summary>
    protected IOpenIddictApplicationStore<TApplication> Store { get; }

    /// <summary>
    /// Determines the number of applications that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of applications in the database.
    /// </returns>
    public virtual ValueTask<long> CountAsync(CancellationToken cancellationToken = default)
        => Store.CountAsync(cancellationToken);

    /// <summary>
    /// Determines the number of applications that match the specified query.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of applications that match the specified query.
    /// </returns>
    public virtual ValueTask<long> CountAsync<TResult>(
        Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.CountAsync(query, cancellationToken);
    }

    /// <summary>
    /// Creates a new application.
    /// </summary>
    /// <param name="application">The application to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual ValueTask CreateAsync(TApplication application, CancellationToken cancellationToken = default)
        => CreateAsync(application, secret: null, cancellationToken);

    /// <summary>
    /// Creates a new application.
    /// Note: the default implementation automatically hashes the client
    /// secret before storing it in the database, for security reasons.
    /// </summary>
    /// <param name="application">The application to create.</param>
    /// <param name="secret">The client secret associated with the application, if applicable.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask CreateAsync(TApplication application, string? secret, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (!string.IsNullOrEmpty(await Store.GetClientSecretAsync(application, cancellationToken)))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0206), nameof(application));
        }

        // If no client type was specified, assume it's a public application if no secret was provided.
        var type = await Store.GetClientTypeAsync(application, cancellationToken);
        if (string.IsNullOrEmpty(type))
        {
            await Store.SetClientTypeAsync(application, string.IsNullOrEmpty(secret) ?
                ClientTypes.Public : ClientTypes.Confidential, cancellationToken);
        }

        // If a client secret was provided, obfuscate it.
        if (!string.IsNullOrEmpty(secret))
        {
            secret = await ObfuscateClientSecretAsync(secret, cancellationToken);
            await Store.SetClientSecretAsync(application, secret, cancellationToken);
        }

        var results = await GetValidationResultsAsync(application, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0207));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.CreateAsync(application, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.AddAsync(application, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TApplication application, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(application, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Creates a new application based on the specified descriptor.
    /// Note: the default implementation automatically hashes the client
    /// secret before storing it in the database, for security reasons.
    /// </summary>
    /// <param name="descriptor">The application descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the application.
    /// </returns>
    public virtual async ValueTask<TApplication> CreateAsync(
        OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        var application = await Store.InstantiateAsync(cancellationToken) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0208));

        await PopulateAsync(application, descriptor, cancellationToken);

        var secret = await Store.GetClientSecretAsync(application, cancellationToken);
        if (!string.IsNullOrEmpty(secret))
        {
            await Store.SetClientSecretAsync(application, secret: null, cancellationToken);
            await CreateAsync(application, secret, cancellationToken);
        }
        else
        {
            await CreateAsync(application, cancellationToken);
        }

        return application;
    }

    /// <summary>
    /// Removes an existing application.
    /// </summary>
    /// <param name="application">The application to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask DeleteAsync(TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(application, cancellationToken);
        }

        await Store.DeleteAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves an application using its client identifier.
    /// </summary>
    /// <param name="identifier">The client identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    public virtual async ValueTask<TApplication?> FindByClientIdAsync(
        string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var application = Options.CurrentValue.DisableEntityCaching ?
            await Store.FindByClientIdAsync(identifier, cancellationToken) :
            await Cache.FindByClientIdAsync(identifier, cancellationToken);

        if (application is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetClientIdAsync(application, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return application;
    }

    /// <summary>
    /// Retrieves an application using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    public virtual async ValueTask<TApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
        }

        var application = Options.CurrentValue.DisableEntityCaching ?
            await Store.FindByIdAsync(identifier, cancellationToken) :
            await Cache.FindByIdAsync(identifier, cancellationToken);

        if (application is null)
        {
            return null;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.
        if (!Options.CurrentValue.DisableAdditionalFiltering &&
            !string.Equals(await Store.GetIdAsync(application, cancellationToken), identifier, StringComparison.Ordinal))
        {
            return null;
        }

        return application;
    }

    /// <summary>
    /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
    /// </summary>
    /// <param name="address">The post_logout_redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified post_logout_redirect_uri.</returns>
    public virtual IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(
        string address, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(address))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
        }

        var applications = Options.CurrentValue.DisableEntityCaching ?
            Store.FindByPostLogoutRedirectUriAsync(address, cancellationToken) :
            Cache.FindByPostLogoutRedirectUriAsync(address, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return applications;
        }

        return ExecuteAsync(cancellationToken);

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var application in applications)
            {
                var addresses = await Store.GetPostLogoutRedirectUrisAsync(application, cancellationToken);
                if (addresses.Contains(address, StringComparer.Ordinal))
                {
                    yield return application;
                }
            }
        }
    }

    /// <summary>
    /// Retrieves all the applications associated with the specified redirect_uri.
    /// </summary>
    /// <param name="address">The redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified redirect_uri.</returns>
    public virtual IAsyncEnumerable<TApplication> FindByRedirectUriAsync(
        string address, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(address))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
        }

        var applications = Options.CurrentValue.DisableEntityCaching ?
            Store.FindByRedirectUriAsync(address, cancellationToken) :
            Cache.FindByRedirectUriAsync(address, cancellationToken);

        if (Options.CurrentValue.DisableAdditionalFiltering)
        {
            return applications;
        }

        // SQL engines like Microsoft SQL Server or MySQL are known to use case-insensitive lookups by default.
        // To ensure a case-sensitive comparison is enforced independently of the database/table/query collation
        // used by the store, a second pass using string.Equals(StringComparison.Ordinal) is manually made here.

        return ExecuteAsync(cancellationToken);

        async IAsyncEnumerable<TApplication> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await foreach (var application in applications)
            {
                var addresses = await Store.GetRedirectUrisAsync(application, cancellationToken);
                if (addresses.Contains(address, StringComparer.Ordinal))
                {
                    yield return application;
                }
            }
        }
    }

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    public virtual ValueTask<TResult?> GetAsync<TResult>(
        Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return GetAsync(static (applications, query) => query(applications), query, cancellationToken);
    }

    /// <summary>
    /// Executes the specified query and returns the first element.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the first element returned when executing the query.
    /// </returns>
    public virtual ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.GetAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Retrieves the client identifier associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client identifier associated with the application.
    /// </returns>
    public virtual ValueTask<string?> GetClientIdAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetClientIdAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the client type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client type of the application (by default, "public").
    /// </returns>
    public virtual ValueTask<string?> GetClientTypeAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetClientTypeAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the consent type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the consent type of the application (by default, "explicit").
    /// </returns>
    public virtual async ValueTask<string?> GetConsentTypeAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        var type = await Store.GetConsentTypeAsync(application, cancellationToken);
        if (string.IsNullOrEmpty(type))
        {
            return ConsentTypes.Explicit;
        }

        return type;
    }

    /// <summary>
    /// Retrieves the display name associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the application.
    /// </returns>
    public virtual ValueTask<string?> GetDisplayNameAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetDisplayNameAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the localized display names associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the application.
    /// </returns>
    public virtual async ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        var names = await Store.GetDisplayNamesAsync(application, cancellationToken);
        if (names is not { Count: > 0 })
        {
            return ImmutableDictionary.Create<CultureInfo, string>();
        }

        return names;
    }

    /// <summary>
    /// Retrieves the unique identifier associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the application.
    /// </returns>
    public virtual ValueTask<string?> GetIdAsync(TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetIdAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the localized display name associated with an application
    /// and corresponding to the current UI culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized display name associated with the application.
    /// </returns>
    public virtual ValueTask<string?> GetLocalizedDisplayNameAsync(
        TApplication application, CancellationToken cancellationToken = default)
        => GetLocalizedDisplayNameAsync(application, CultureInfo.CurrentUICulture, cancellationToken);

    /// <summary>
    /// Retrieves the localized display name associated with an application
    /// and corresponding to the specified culture or one of its parents.
    /// If no matching value can be found, the non-localized value is returned.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="culture">The culture (typically <see cref="CultureInfo.CurrentUICulture"/>).</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the matching localized display name associated with the application.
    /// </returns>
    public virtual async ValueTask<string?> GetLocalizedDisplayNameAsync(
        TApplication application, CultureInfo culture, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (culture is null)
        {
            throw new ArgumentNullException(nameof(culture));
        }

        var names = await Store.GetDisplayNamesAsync(application, cancellationToken);
        if (names is not { Count: > 0 })
        {
            return await Store.GetDisplayNameAsync(application, cancellationToken);
        }

        do
        {
            if (names.TryGetValue(culture, out var name))
            {
                return name;
            }

            culture = culture.Parent;
        }

        while (culture != CultureInfo.InvariantCulture);

        return await Store.GetDisplayNameAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the permissions associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the permissions associated with the application.
    /// </returns>
    public virtual ValueTask<ImmutableArray<string>> GetPermissionsAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetPermissionsAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the logout callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the post_logout_redirect_uri associated with the application.
    /// </returns>
    public virtual ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetPostLogoutRedirectUrisAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the additional properties associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the application.
    /// </returns>
    public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetPropertiesAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the redirect_uri associated with the application.
    /// </returns>
    public virtual ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetRedirectUrisAsync(application, cancellationToken);
    }

    /// <summary>
    /// Retrieves the requirements associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the requirements associated with the application.
    /// </returns>
    public virtual ValueTask<ImmutableArray<string>> GetRequirementsAsync(
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        return Store.GetRequirementsAsync(application, cancellationToken);
    }

    /// <summary>
    /// Determines whether a given application has the specified client type.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="type">The expected client type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the application has the specified client type, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasClientTypeAsync(
        TApplication application, string type, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0209), nameof(type));
        }

        return string.Equals(await GetClientTypeAsync(application, cancellationToken), type, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether a given application has the specified consent type.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="type">The expected consent type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the application has the specified consent type, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasConsentTypeAsync(
        TApplication application, string type, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (string.IsNullOrEmpty(type))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0210), nameof(type));
        }

        return string.Equals(await GetConsentTypeAsync(application, cancellationToken), type, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Determines whether the specified permission has been granted to the application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="permission">The permission.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the application has been granted the specified permission, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasPermissionAsync(
        TApplication application, string permission, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (string.IsNullOrEmpty(permission))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0211), nameof(permission));
        }

        return (await GetPermissionsAsync(application, cancellationToken)).Contains(permission, StringComparer.Ordinal);
    }

    /// <summary>
    /// Determines whether the specified requirement has been enforced for the specified application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="requirement">The requirement.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the requirement has been enforced for the specified application, <see langword="false"/> otherwise.</returns>
    public virtual async ValueTask<bool> HasRequirementAsync(
        TApplication application, string requirement, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (string.IsNullOrEmpty(requirement))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0212), nameof(requirement));
        }

        return (await GetRequirementsAsync(application, cancellationToken)).Contains(requirement, StringComparer.Ordinal);
    }

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TApplication> ListAsync(
        int? count = null, int? offset = null, CancellationToken cancellationToken = default)
        => Store.ListAsync(count, offset, cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResult> ListAsync<TResult>(
        Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return ListAsync(static (applications, query) => query(applications), query, cancellationToken);
    }

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return Store.ListAsync(query, state, cancellationToken);
    }

    /// <summary>
    /// Populates the application using the specified descriptor.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(TApplication application,
        OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        await Store.SetClientIdAsync(application, descriptor.ClientId, cancellationToken);
        await Store.SetClientSecretAsync(application, descriptor.ClientSecret, cancellationToken);
        await Store.SetClientTypeAsync(application, descriptor.Type, cancellationToken);
        await Store.SetConsentTypeAsync(application, descriptor.ConsentType, cancellationToken);
        await Store.SetDisplayNameAsync(application, descriptor.DisplayName, cancellationToken);
        await Store.SetDisplayNamesAsync(application, descriptor.DisplayNames.ToImmutableDictionary(), cancellationToken);
        await Store.SetPermissionsAsync(application, descriptor.Permissions.ToImmutableArray(), cancellationToken);
        await Store.SetPostLogoutRedirectUrisAsync(application, ImmutableArray.CreateRange(
            descriptor.PostLogoutRedirectUris.Select(address => address.OriginalString)), cancellationToken);
        await Store.SetPropertiesAsync(application, descriptor.Properties.ToImmutableDictionary(), cancellationToken);
        await Store.SetRedirectUrisAsync(application, ImmutableArray.CreateRange(
            descriptor.RedirectUris.Select(address => address.OriginalString)), cancellationToken);
        await Store.SetRequirementsAsync(application, descriptor.Requirements.ToImmutableArray(), cancellationToken);
    }

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the application.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask PopulateAsync(
        OpenIddictApplicationDescriptor descriptor,
        TApplication application, CancellationToken cancellationToken = default)
    {
        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        descriptor.ClientId = await Store.GetClientIdAsync(application, cancellationToken);
        descriptor.ClientSecret = await Store.GetClientSecretAsync(application, cancellationToken);
        descriptor.ConsentType = await Store.GetConsentTypeAsync(application, cancellationToken);
        descriptor.DisplayName = await Store.GetDisplayNameAsync(application, cancellationToken);
        descriptor.Type = await Store.GetClientTypeAsync(application, cancellationToken);
        descriptor.Permissions.Clear();
        descriptor.Permissions.UnionWith(await Store.GetPermissionsAsync(application, cancellationToken));
        descriptor.Requirements.Clear();
        descriptor.Requirements.UnionWith(await Store.GetRequirementsAsync(application, cancellationToken));

        descriptor.DisplayNames.Clear();
        foreach (var pair in await Store.GetDisplayNamesAsync(application, cancellationToken))
        {
            descriptor.DisplayNames.Add(pair.Key, pair.Value);
        }

        descriptor.PostLogoutRedirectUris.Clear();
        foreach (var address in await Store.GetPostLogoutRedirectUrisAsync(application, cancellationToken))
        {
            // Ensure the address is not null or empty.
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0213));
            }

            // Ensure the address is a valid absolute URL.
            if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0214));
            }

            descriptor.PostLogoutRedirectUris.Add(uri);
        }

        descriptor.Properties.Clear();
        foreach (var pair in await Store.GetPropertiesAsync(application, cancellationToken))
        {
            descriptor.Properties.Add(pair.Key, pair.Value);
        }

        descriptor.RedirectUris.Clear();
        foreach (var address in await Store.GetRedirectUrisAsync(application, cancellationToken))
        {
            // Ensure the address is not null or empty.
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0213));
            }

            // Ensure the address is a valid absolute URL.
            if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0214));
            }

            descriptor.RedirectUris.Add(uri);
        }
    }

    /// <summary>
    /// Updates an existing application.
    /// </summary>
    /// <param name="application">The application to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TApplication application, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        var results = await GetValidationResultsAsync(application, cancellationToken);
        if (results.Any(result => result != ValidationResult.Success))
        {
            var builder = new StringBuilder();
            builder.AppendLine(SR.GetResourceString(SR.ID0215));
            builder.AppendLine();

            foreach (var result in results)
            {
                builder.AppendLine(result.ErrorMessage);
            }

            throw new ValidationException(builder.ToString(), results);
        }

        await Store.UpdateAsync(application, cancellationToken);

        if (!Options.CurrentValue.DisableEntityCaching)
        {
            await Cache.RemoveAsync(application, cancellationToken);
            await Cache.AddAsync(application, cancellationToken);
        }

        async Task<ImmutableArray<ValidationResult>> GetValidationResultsAsync(
            TApplication application, CancellationToken cancellationToken)
        {
            var builder = ImmutableArray.CreateBuilder<ValidationResult>();

            await foreach (var result in ValidateAsync(application, cancellationToken))
            {
                builder.Add(result);
            }

            return builder.ToImmutable();
        }
    }

    /// <summary>
    /// Updates an existing application and replaces the existing secret.
    /// Note: the default implementation automatically hashes the client
    /// secret before storing it in the database, for security reasons.
    /// </summary>
    /// <param name="application">The application to update.</param>
    /// <param name="secret">The client secret associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TApplication application, string? secret, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (string.IsNullOrEmpty(secret))
        {
            await Store.SetClientSecretAsync(application, null, cancellationToken);
        }

        else
        {
            secret = await ObfuscateClientSecretAsync(secret, cancellationToken);
            await Store.SetClientSecretAsync(application, secret, cancellationToken);
        }

        await UpdateAsync(application, cancellationToken);
    }

    /// <summary>
    /// Updates an existing application.
    /// </summary>
    /// <param name="application">The application to update.</param>
    /// <param name="descriptor">The descriptor used to update the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    public virtual async ValueTask UpdateAsync(TApplication application,
        OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (descriptor is null)
        {
            throw new ArgumentNullException(nameof(descriptor));
        }

        // Store the original client secret for later comparison.
        var comparand = await Store.GetClientSecretAsync(application, cancellationToken);
        await PopulateAsync(application, descriptor, cancellationToken);

        // If the client secret was updated, use the overload accepting a secret parameter.
        var secret = await Store.GetClientSecretAsync(application, cancellationToken);
        if (!string.Equals(secret, comparand, StringComparison.Ordinal))
        {
            await UpdateAsync(application, secret, cancellationToken);

            return;
        }

        await UpdateAsync(application, cancellationToken);
    }

    /// <summary>
    /// Validates the application to ensure it's in a consistent state.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the application.</returns>
    public virtual async IAsyncEnumerable<ValidationResult> ValidateAsync(
        TApplication application, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        // Ensure the client_id is not null or empty and is not already used for a different application.
        var identifier = await Store.GetClientIdAsync(application, cancellationToken);
        if (string.IsNullOrEmpty(identifier))
        {
            yield return new ValidationResult(SR.GetResourceString(SR.ID2036));
        }

        else
        {
            // Note: depending on the database/table/query collation used by the store, an application
            // whose client_id doesn't exactly match the specified value may be returned (e.g because
            // the casing is different). To avoid issues when the client identifier is part of an index
            // using the same collation, an error is added even if the two identifiers don't exactly match.
            var other = await Store.FindByClientIdAsync(identifier, cancellationToken);
            if (other is not null && !string.Equals(
                await Store.GetIdAsync(other, cancellationToken),
                await Store.GetIdAsync(application, cancellationToken), StringComparison.Ordinal))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2111));
            }
        }

        var type = await Store.GetClientTypeAsync(application, cancellationToken);
        if (string.IsNullOrEmpty(type))
        {
            yield return new ValidationResult(SR.GetResourceString(SR.ID2050));
        }

        else
        {
            // Ensure the application type is supported by the manager.
            if (!string.Equals(type, ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2112));
            }

            // Ensure a client secret was specified if the client is a confidential application.
            var secret = await Store.GetClientSecretAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(secret) && string.Equals(type, ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2113));
            }

            // Ensure no client secret was specified if the client is a public application.
            else if (!string.IsNullOrEmpty(secret) && string.Equals(type, ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2114));
            }
        }

        // When callback URLs are specified, ensure they are valid and spec-compliant.
        // See https://tools.ietf.org/html/rfc6749#section-3.1 for more information.
        foreach (var address in ImmutableArray.Create<string>()
            .AddRange(await Store.GetPostLogoutRedirectUrisAsync(application, cancellationToken))
            .AddRange(await Store.GetRedirectUrisAsync(application, cancellationToken)))
        {
            // Ensure the address is not null or empty.
            if (string.IsNullOrEmpty(address))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2061));

                break;
            }

            // Ensure the address is a valid absolute URL.
            if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri) || !uri.IsWellFormedOriginalString())
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2062));

                break;
            }

            // Ensure the address doesn't contain a fragment.
            if (!string.IsNullOrEmpty(uri.Fragment))
            {
                yield return new ValidationResult(SR.GetResourceString(SR.ID2115));

                break;
            }

            // To prevent issuer fixation attacks where a malicious client would specify an "iss" parameter
            // in the callback URL, ensure the query - if present - doesn't include an "iss" parameter.
            if (!string.IsNullOrEmpty(uri.Query))
            {
                var parameters = OpenIddictHelpers.ParseQuery(uri.Query);
                if (parameters.ContainsKey(Parameters.Iss))
                {
                    yield return new ValidationResult(SR.FormatID2134(Parameters.Iss));

                    break;
                }
            }
        }
    }

    /// <summary>
    /// Validates the client_secret associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="secret">The secret that should be compared to the client_secret stored in the database.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns a boolean indicating whether the client secret was valid.
    /// </returns>
    public virtual async ValueTask<bool> ValidateClientSecretAsync(
        TApplication application, string secret, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }
        if (string.IsNullOrEmpty(secret))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0216), nameof(secret));
        }

        if (await HasClientTypeAsync(application, ClientTypes.Public, cancellationToken))
        {
            Logger.LogWarning(SR.GetResourceString(SR.ID6159));

            return false;
        }

        var value = await Store.GetClientSecretAsync(application, cancellationToken);
        if (string.IsNullOrEmpty(value))
        {
            Logger.LogError(SR.GetResourceString(SR.ID6160), await GetClientIdAsync(application, cancellationToken));

            return false;
        }

        if (!await ValidateClientSecretAsync(secret, value, cancellationToken))
        {
            Logger.LogInformation(SR.GetResourceString(SR.ID6161), await GetClientIdAsync(application, cancellationToken));

            return false;
        }

        return true;
    }

    /// <summary>
    /// Validates the post_logout_redirect_uri to ensure it's associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="address">The address that should be compared to one of the post_logout_redirect_uri stored in the database.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <remarks>Note: if no client_id parameter is specified in logout requests, this method may not be called.</remarks>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns a boolean indicating whether the post_logout_redirect_uri was valid.
    /// </returns>
    public virtual async ValueTask<bool> ValidatePostLogoutRedirectUriAsync(
        TApplication application, string address, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (string.IsNullOrEmpty(address))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
        }

        foreach (var uri in await Store.GetPostLogoutRedirectUrisAsync(application, cancellationToken))
        {
            // Note: the post_logout_redirect_uri must be compared using case-sensitive "Simple String Comparison".
            if (string.Equals(uri, address, StringComparison.Ordinal))
            {
                return true;
            }
        }

        Logger.LogInformation(SR.GetResourceString(SR.ID6202), address, await GetClientIdAsync(application, cancellationToken));

        return false;
    }

    /// <summary>
    /// Validates the redirect_uri to ensure it's associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="address">The address that should be compared to one of the redirect_uri stored in the database.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns a boolean indicating whether the redirect_uri was valid.
    /// </returns>
    public virtual async ValueTask<bool> ValidateRedirectUriAsync(
        TApplication application, string address, CancellationToken cancellationToken = default)
    {
        if (application is null)
        {
            throw new ArgumentNullException(nameof(application));
        }

        if (string.IsNullOrEmpty(address))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
        }

        foreach (var uri in await Store.GetRedirectUrisAsync(application, cancellationToken))
        {
            // Note: the redirect_uri must be compared using case-sensitive "Simple String Comparison".
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest for more information.
            if (string.Equals(uri, address, StringComparison.Ordinal))
            {
                return true;
            }
        }

        Logger.LogInformation(SR.GetResourceString(SR.ID6162), address, await GetClientIdAsync(application, cancellationToken));

        return false;
    }

    /// <summary>
    /// Obfuscates the specified client secret so it can be safely stored in a database.
    /// By default, this method returns a complex hashed representation computed using PBKDF2.
    /// </summary>
    /// <param name="secret">The client secret.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    protected virtual ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(secret))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0216), nameof(secret));
        }

        // Note: the PRF, iteration count, salt length and key length currently all match the default values
        // used by CryptoHelper and ASP.NET Core Identity but this may change in the future, if necessary.

        var salt = new byte[128 / 8];

#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
        RandomNumberGenerator.Fill(salt);
#else
        using var generator = RandomNumberGenerator.Create();
        generator.GetBytes(salt);
#endif

        var hash = HashSecret(secret, salt, HashAlgorithmName.SHA256, iterations: 10_000, length: 256 / 8);

        return new(
#if SUPPORTS_BASE64_SPAN_CONVERSION
            Convert.ToBase64String(hash)
#else
            Convert.ToBase64String(hash.ToArray())
#endif
        );

        // Note: the following logic deliberately uses the same format as CryptoHelper (used in OpenIddict 1.x/2.x),
        // which was itself based on ASP.NET Core Identity's latest hashed password format. This guarantees that
        // secrets hashed using a recent OpenIddict version can still be read by older packages (and vice versa).

        static ReadOnlySpan<byte> HashSecret(string secret, ReadOnlySpan<byte> salt,
            HashAlgorithmName algorithm, int iterations, int length)
        {
            var key = DeriveKey(secret, salt, algorithm, iterations, length);
            var payload = new Span<byte>(new byte[13 + salt.Length + key.Length]);

            // Write the format marker.
            payload[0] = 0x01;

            // Write the hashing algorithm version.
            BinaryPrimitives.WriteUInt32BigEndian(payload.Slice(1, 4), algorithm switch
            {
                var name when name == HashAlgorithmName.SHA1   => 0,
                var name when name == HashAlgorithmName.SHA256 => 1,
                var name when name == HashAlgorithmName.SHA512 => 2,

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0217))
            });

            // Write the iteration count of the algorithm.
            BinaryPrimitives.WriteUInt32BigEndian(payload.Slice(5, 8), (uint) iterations);

            // Write the size of the salt.
            BinaryPrimitives.WriteUInt32BigEndian(payload.Slice(9, 12), (uint) salt.Length);

            // Write the salt.
            salt.CopyTo(payload.Slice(13));

            // Write the subkey.
            key.CopyTo(payload.Slice(13 + salt.Length));

            return payload;
        }
    }

    /// <summary>
    /// Validates the specified value to ensure it corresponds to the client secret.
    /// Note: when overriding this method, using a time-constant comparer is strongly recommended.
    /// </summary>
    /// <param name="secret">The client secret to compare to the value stored in the database.</param>
    /// <param name="comparand">The value stored in the database, which is usually a hashed representation of the secret.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns a boolean indicating whether the specified value was valid.
    /// </returns>
    protected virtual ValueTask<bool> ValidateClientSecretAsync(
        string secret, string comparand, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(secret))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0216), nameof(secret));
        }

        if (string.IsNullOrEmpty(comparand))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0218), nameof(comparand));
        }

        try
        {
            return new(VerifyHashedSecret(comparand, secret));
        }

        catch (Exception exception)
        {
            Logger.LogWarning(exception, SR.GetResourceString(SR.ID6163));

            return new(false);
        }

        // Note: the following logic deliberately uses the same format as CryptoHelper (used in OpenIddict 1.x/2.x),
        // which was itself based on ASP.NET Core Identity's latest hashed password format. This guarantees that
        // secrets hashed using a recent OpenIddict version can still be read by older packages (and vice versa).

        static bool VerifyHashedSecret(string hash, string secret)
        {
            var payload = new ReadOnlySpan<byte>(Convert.FromBase64String(hash));
            if (payload.Length is 0)
            {
                return false;
            }

            // Verify the hashing format version.
            if (payload[0] is not 0x01)
            {
                return false;
            }

            // Read the hashing algorithm version.
            var algorithm = (int) BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(1, 4)) switch
            {
                0 => HashAlgorithmName.SHA1,
                1 => HashAlgorithmName.SHA256,
                2 => HashAlgorithmName.SHA512,

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0217))
            };

            // Read the iteration count of the algorithm.
            var iterations = (int) BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(5, 8));

            // Read the size of the salt and ensure it's more than 128 bits.
            var saltLength = (int) BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(9, 12));
            if (saltLength < 128 / 8)
            {
                return false;
            }

            // Read the salt.
            var salt = payload.Slice(13, saltLength);

            // Ensure the derived key length is more than 128 bits.
            var keyLength = payload.Length - 13 - salt.Length;
            if (keyLength < 128 / 8)
            {
                return false;
            }

#if SUPPORTS_TIME_CONSTANT_COMPARISONS
            return CryptographicOperations.FixedTimeEquals(
                left: payload.Slice(13 + salt.Length, keyLength),
                right: DeriveKey(secret, salt, algorithm, iterations, keyLength));
#else
            return Arrays.ConstantTimeAreEqual(
                a: payload.Slice(13 + salt.Length, keyLength).ToArray(),
                b: DeriveKey(secret, salt, algorithm, iterations, keyLength));
#endif
        }
    }

    [SuppressMessage("Security", "CA5379:Do not use weak key derivation function algorithm",
        Justification = "The SHA-1 digest algorithm is still supported for backward compatibility.")]
    private static byte[] DeriveKey(string secret, ReadOnlySpan<byte> salt,
        HashAlgorithmName algorithm, int iterations, int length)
    {
#if SUPPORTS_KEY_DERIVATION_WITH_SPECIFIED_HASH_ALGORITHM
        using var generator = new Rfc2898DeriveBytes(secret, salt.ToArray(), iterations, algorithm);
        return generator.GetBytes(length);
#else
        var generator = new Pkcs5S2ParametersGenerator(algorithm switch
        {
            var name when name == HashAlgorithmName.SHA1   => new Sha1Digest(),
            var name when name == HashAlgorithmName.SHA256 => new Sha256Digest(),
            var name when name == HashAlgorithmName.SHA512 => new Sha512Digest(),

            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0217))
        });

        generator.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(secret.ToCharArray()), salt.ToArray(), iterations);

        var key = (KeyParameter) generator.GenerateDerivedMacParameters(length * 8);
        return key.GetKey();
#endif
    }

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictApplicationManager.CountAsync(CancellationToken cancellationToken)
        => CountAsync(cancellationToken);

    /// <inheritdoc/>
    ValueTask<long> IOpenIddictApplicationManager.CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => CountAsync(query, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object> IOpenIddictApplicationManager.CreateAsync(OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken)
        => await CreateAsync(descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.CreateAsync(object application, CancellationToken cancellationToken)
        => CreateAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.CreateAsync(object application, string? secret, CancellationToken cancellationToken)
        => CreateAsync((TApplication) application, secret, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.DeleteAsync(object application, CancellationToken cancellationToken)
        => DeleteAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictApplicationManager.FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByClientIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    async ValueTask<object?> IOpenIddictApplicationManager.FindByIdAsync(string identifier, CancellationToken cancellationToken)
        => await FindByIdAsync(identifier, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictApplicationManager.FindByPostLogoutRedirectUriAsync(string address, CancellationToken cancellationToken)
        => FindByPostLogoutRedirectUriAsync(address, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictApplicationManager.FindByRedirectUriAsync(string address, CancellationToken cancellationToken)
        => FindByRedirectUriAsync(address, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictApplicationManager.GetAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, cancellationToken);

    /// <inheritdoc/>
    ValueTask<TResult?> IOpenIddictApplicationManager.GetAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken) where TResult : default
        => GetAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictApplicationManager.GetClientIdAsync(object application, CancellationToken cancellationToken)
        => GetClientIdAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictApplicationManager.GetClientTypeAsync(object application, CancellationToken cancellationToken)
        => GetClientTypeAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictApplicationManager.GetConsentTypeAsync(object application, CancellationToken cancellationToken)
        => GetConsentTypeAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictApplicationManager.GetDisplayNameAsync(object application, CancellationToken cancellationToken)
        => GetDisplayNameAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<CultureInfo, string>> IOpenIddictApplicationManager.GetDisplayNamesAsync(object application, CancellationToken cancellationToken)
        => GetDisplayNamesAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictApplicationManager.GetIdAsync(object application, CancellationToken cancellationToken)
        => GetIdAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictApplicationManager.GetLocalizedDisplayNameAsync(object application, CancellationToken cancellationToken)
        => GetLocalizedDisplayNameAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<string?> IOpenIddictApplicationManager.GetLocalizedDisplayNameAsync(object application, CultureInfo culture, CancellationToken cancellationToken)
        => GetLocalizedDisplayNameAsync((TApplication) application, culture, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableArray<string>> IOpenIddictApplicationManager.GetPermissionsAsync(object application, CancellationToken cancellationToken)
        => GetPermissionsAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableArray<string>> IOpenIddictApplicationManager.GetPostLogoutRedirectUrisAsync(object application, CancellationToken cancellationToken)
        => GetPostLogoutRedirectUrisAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableDictionary<string, JsonElement>> IOpenIddictApplicationManager.GetPropertiesAsync(object application, CancellationToken cancellationToken)
        => GetPropertiesAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableArray<string>> IOpenIddictApplicationManager.GetRedirectUrisAsync(object application, CancellationToken cancellationToken)
        => GetRedirectUrisAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<ImmutableArray<string>> IOpenIddictApplicationManager.GetRequirementsAsync(object application, CancellationToken cancellationToken)
        => GetRequirementsAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictApplicationManager.HasClientTypeAsync(object application, string type, CancellationToken cancellationToken)
        => HasClientTypeAsync((TApplication) application, type, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictApplicationManager.HasConsentTypeAsync(object application, string type, CancellationToken cancellationToken)
        => HasConsentTypeAsync((TApplication) application, type, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictApplicationManager.HasPermissionAsync(object application, string permission, CancellationToken cancellationToken)
        => HasPermissionAsync((TApplication) application, permission, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictApplicationManager.HasRequirementAsync(object application, string requirement, CancellationToken cancellationToken)
        => HasRequirementAsync((TApplication) application, requirement, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<object> IOpenIddictApplicationManager.ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        => ListAsync(count, offset, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictApplicationManager.ListAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        => ListAsync(query, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<TResult> IOpenIddictApplicationManager.ListAsync<TState, TResult>(Func<IQueryable<object>, TState, IQueryable<TResult>> query, TState state, CancellationToken cancellationToken)
        => ListAsync(query, state, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.PopulateAsync(OpenIddictApplicationDescriptor descriptor, object application, CancellationToken cancellationToken)
        => PopulateAsync(descriptor, (TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.PopulateAsync(object application, OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken)
        => PopulateAsync((TApplication) application, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.UpdateAsync(object application, CancellationToken cancellationToken)
        => UpdateAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.UpdateAsync(object application, OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken)
        => UpdateAsync((TApplication) application, descriptor, cancellationToken);

    /// <inheritdoc/>
    ValueTask IOpenIddictApplicationManager.UpdateAsync(object application, string? secret, CancellationToken cancellationToken)
        => UpdateAsync((TApplication) application, secret, cancellationToken);

    /// <inheritdoc/>
    IAsyncEnumerable<ValidationResult> IOpenIddictApplicationManager.ValidateAsync(object application, CancellationToken cancellationToken)
        => ValidateAsync((TApplication) application, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictApplicationManager.ValidateClientSecretAsync(object application, string secret, CancellationToken cancellationToken)
        => ValidateClientSecretAsync((TApplication) application, secret, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictApplicationManager.ValidatePostLogoutRedirectUriAsync(object application, string address, CancellationToken cancellationToken)
        => ValidatePostLogoutRedirectUriAsync((TApplication) application, address, cancellationToken);

    /// <inheritdoc/>
    ValueTask<bool> IOpenIddictApplicationManager.ValidateRedirectUriAsync(object application, string address, CancellationToken cancellationToken)
        => ValidateRedirectUriAsync((TApplication) application, address, cancellationToken);
}
