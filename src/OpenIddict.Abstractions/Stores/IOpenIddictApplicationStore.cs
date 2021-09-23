/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the applications stored in a database.
/// </summary>
/// <typeparam name="TApplication">The type of the Application entity.</typeparam>
public interface IOpenIddictApplicationStore<TApplication> where TApplication : class
{
    /// <summary>
    /// Determines the number of applications that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of applications in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken);

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
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<TApplication>, IQueryable<TResult>> query, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new application.
    /// </summary>
    /// <param name="application">The application to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask CreateAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Removes an existing application.
    /// </summary>
    /// <param name="application">The application to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask DeleteAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves an application using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    ValueTask<TApplication?> FindByIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves an application using its client identifier.
    /// </summary>
    /// <param name="identifier">The client identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    ValueTask<TApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
    /// </summary>
    /// <param name="address">The post_logout_redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified post_logout_redirect_uri.</returns>
    IAsyncEnumerable<TApplication> FindByPostLogoutRedirectUriAsync(string address, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all the applications associated with the specified redirect_uri.
    /// </summary>
    /// <param name="address">The redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified redirect_uri.</returns>
    IAsyncEnumerable<TApplication> FindByRedirectUriAsync(string address, CancellationToken cancellationToken);

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
    ValueTask<TResult?> GetAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the client identifier associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client identifier associated with the application.
    /// </returns>
    ValueTask<string?> GetClientIdAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the client secret associated with an application.
    /// Note: depending on the manager used to create the application,
    /// the client secret may be hashed for security reasons.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client secret associated with the application.
    /// </returns>
    ValueTask<string?> GetClientSecretAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the client type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client type of the application (by default, "public").
    /// </returns>
    ValueTask<string?> GetClientTypeAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the consent type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the consent type of the application (by default, "explicit").
    /// </returns>
    ValueTask<string?> GetConsentTypeAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the display name associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the application.
    /// </returns>
    ValueTask<string?> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the localized display names associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the application.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the unique identifier associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the application.
    /// </returns>
    ValueTask<string?> GetIdAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the permissions associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the permissions associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetPermissionsAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the logout callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the post_logout_redirect_uri associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the additional properties associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the application.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the redirect_uri associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves the requirements associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the requirements associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetRequirementsAsync(TApplication application, CancellationToken cancellationToken);

    /// <summary>
    /// Instantiates a new application.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the instantiated application, that can be persisted in the database.
    /// </returns>
    ValueTask<TApplication> InstantiateAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TApplication> ListAsync(int? count, int? offset, CancellationToken cancellationToken);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TState">The state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="state">The optional state.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
        Func<IQueryable<TApplication>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the client identifier associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="identifier">The client identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetClientIdAsync(TApplication application, string? identifier, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the client secret associated with an application.
    /// Note: depending on the manager used to create the application,
    /// the client secret may be hashed for security reasons.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="secret">The client secret associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetClientSecretAsync(TApplication application, string? secret, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the client type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="type">The client type associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetClientTypeAsync(TApplication application, string? type, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the consent type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="type">The consent type associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetConsentTypeAsync(TApplication application, string? type, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the display name associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="name">The display name associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDisplayNameAsync(TApplication application, string? name, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the localized display names associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="names">The localized display names associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetDisplayNamesAsync(TApplication application,
        ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the permissions associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="permissions">The permissions associated with the application </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPermissionsAsync(TApplication application, ImmutableArray<string> permissions, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the logout callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="addresses">The logout callback addresses associated with the application </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPostLogoutRedirectUrisAsync(TApplication application,
        ImmutableArray<string> addresses, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the additional properties associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="properties">The additional properties associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetPropertiesAsync(TApplication application,
        ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="addresses">The callback addresses associated with the application </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetRedirectUrisAsync(TApplication application,
        ImmutableArray<string> addresses, CancellationToken cancellationToken);

    /// <summary>
    /// Sets the requirements associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="requirements">The requirements associated with the application </param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask SetRequirementsAsync(TApplication application, ImmutableArray<string> requirements, CancellationToken cancellationToken);

    /// <summary>
    /// Updates an existing application.
    /// </summary>
    /// <param name="application">The application to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    ValueTask UpdateAsync(TApplication application, CancellationToken cancellationToken);
}
