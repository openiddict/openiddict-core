/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OpenIddict.Abstractions;

/// <summary>
/// Provides methods allowing to manage the applications stored in the store.
/// Note: this interface is not meant to be implemented by custom managers,
/// that should inherit from the generic OpenIddictApplicationManager class.
/// It is primarily intended to be used by services that cannot easily depend
/// on the generic application manager. The actual application entity type
/// is automatically determined at runtime based on the OpenIddict core options.
/// </summary>
public interface IOpenIddictApplicationManager
{
    /// <summary>
    /// Determines the number of applications that exist in the database.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the number of applications in the database.
    /// </returns>
    ValueTask<long> CountAsync(CancellationToken cancellationToken = default);

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
    ValueTask<long> CountAsync<TResult>(Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

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
    ValueTask<object> CreateAsync(OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new application.
    /// </summary>
    /// <param name="application">The application to create.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask CreateAsync(object application, CancellationToken cancellationToken = default);

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
    ValueTask CreateAsync(object application, string? secret, CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes an existing application.
    /// </summary>
    /// <param name="application">The application to delete.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask DeleteAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves an application using its client identifier.
    /// </summary>
    /// <param name="identifier">The client identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    ValueTask<object?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves an application using its unique identifier.
    /// </summary>
    /// <param name="identifier">The unique identifier associated with the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client application corresponding to the identifier.
    /// </returns>
    ValueTask<object?> FindByIdAsync(string identifier, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
    /// </summary>
    /// <param name="address">The post_logout_redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified post_logout_redirect_uri.</returns>
    IAsyncEnumerable<object> FindByPostLogoutRedirectUriAsync(string address, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all the applications associated with the specified redirect_uri.
    /// </summary>
    /// <param name="address">The redirect_uri associated with the applications.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The client applications corresponding to the specified redirect_uri.</returns>
    IAsyncEnumerable<object> FindByRedirectUriAsync(string address, CancellationToken cancellationToken = default);

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
    ValueTask<TResult?> GetAsync<TResult>(
        Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

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
        Func<IQueryable<object>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the client identifier associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client identifier associated with the application.
    /// </returns>
    ValueTask<string?> GetClientIdAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the client type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the client type of the application (by default, "public").
    /// </returns>
    ValueTask<string?> GetClientTypeAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the consent type associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the consent type of the application (by default, "explicit").
    /// </returns>
    ValueTask<string?> GetConsentTypeAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the display name associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the display name associated with the application.
    /// </returns>
    ValueTask<string?> GetDisplayNameAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the localized display names associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the localized display names associated with the application.
    /// </returns>
    ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the unique identifier associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns the unique identifier associated with the application.
    /// </returns>
    ValueTask<string?> GetIdAsync(object application, CancellationToken cancellationToken = default);

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
    ValueTask<string?> GetLocalizedDisplayNameAsync(object application, CancellationToken cancellationToken = default);

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
    ValueTask<string?> GetLocalizedDisplayNameAsync(object application, CultureInfo culture, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the permissions associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the permissions associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetPermissionsAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the logout callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the post_logout_redirect_uri associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the additional properties associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the additional properties associated with the application.
    /// </returns>
    ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the callback addresses associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the redirect_uri associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the requirements associated with an application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask{TResult}"/> that can be used to monitor the asynchronous operation,
    /// whose result returns all the requirements associated with the application.
    /// </returns>
    ValueTask<ImmutableArray<string>> GetRequirementsAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given application has the specified client type.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="type">The expected client type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><c>true</c> if the application has the specified client type, <c>false</c> otherwise.</returns>
    ValueTask<bool> HasClientTypeAsync(object application, string type, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether a given application has the specified consent type.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="type">The expected consent type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><c>true</c> if the application has the specified consent type, <c>false</c> otherwise.</returns>
    ValueTask<bool> HasConsentTypeAsync(object application, string type, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether the specified permission has been granted to the application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="permission">The permission.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><c>true</c> if the application has been granted the specified permission, <c>false</c> otherwise.</returns>
    ValueTask<bool> HasPermissionAsync(object application, string permission, CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether the specified requirement has been enforced for the specified application.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="requirement">The requirement.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><c>true</c> if the requirement has been enforced for the specified application, <c>false</c> otherwise.</returns>
    ValueTask<bool> HasRequirementAsync(object application, string requirement, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <param name="count">The number of results to return.</param>
    /// <param name="offset">The number of results to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<object> ListAsync(
        int? count = null, int? offset = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executes the specified query and returns all the corresponding elements.
    /// </summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="query">The query to execute.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>All the elements returned when executing the specified query.</returns>
    IAsyncEnumerable<TResult> ListAsync<TResult>(
        Func<IQueryable<object>, IQueryable<TResult>> query, CancellationToken cancellationToken = default);

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
        Func<IQueryable<object>, TState, IQueryable<TResult>> query,
        TState state, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the specified descriptor using the properties exposed by the application.
    /// </summary>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(OpenIddictApplicationDescriptor descriptor, object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Populates the application using the specified descriptor.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask PopulateAsync(object application, OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing application.
    /// </summary>
    /// <param name="application">The application to update.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object application, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing application.
    /// </summary>
    /// <param name="application">The application to update.</param>
    /// <param name="descriptor">The descriptor used to update the application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
    /// </returns>
    ValueTask UpdateAsync(object application, OpenIddictApplicationDescriptor descriptor, CancellationToken cancellationToken = default);

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
    ValueTask UpdateAsync(object application, string secret, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates the application to ensure it's in a consistent state.
    /// </summary>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation error encountered when validating the application.</returns>
    IAsyncEnumerable<ValidationResult> ValidateAsync(object application, CancellationToken cancellationToken = default);

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
    ValueTask<bool> ValidateClientSecretAsync(object application, string secret, CancellationToken cancellationToken = default);

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
    ValueTask<bool> ValidateRedirectUriAsync(object application, string address, CancellationToken cancellationToken = default);
}
