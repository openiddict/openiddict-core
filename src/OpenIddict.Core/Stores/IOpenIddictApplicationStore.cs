/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace OpenIddict {
    /// <summary>
    /// Provides an abstraction for a store which manages client applications.
    /// </summary>
    /// <typeparam name="TApplication">The type encapsulating a client application.</typeparam>
    public interface IOpenIddictApplicationStore<TApplication> where TApplication : class {
        /// <summary>
        /// Creates a new application.
        /// </summary>
        /// <param name="application">The application to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        Task<string> CreateAsync(TApplication application, CancellationToken cancellationToken);

        /// <summary>
        /// Finds and returns an application, if any, which has the specified <paramref name="id"/>.
        /// </summary>
        /// <param name="id">The identifier of application entity to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        Task<TApplication> FindByIdAsync(string id, CancellationToken cancellationToken);

        /// <summary>
        /// Finds and returns an application, if any, which has the specified client_id.
        /// </summary>
        /// <param name="clientId">The identifier of client application to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        Task<TApplication> FindByClientIdAsync(string clientId, CancellationToken cancellationToken);

        /// <summary>
        /// Finds and returns an application, if any, which has the specified post_logout_redirect_uri.
        /// </summary>
        /// <param name="url">The post logout redirect URI of application to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
        /// returns the client application corresponding to the post logout redirect URI.
        /// </returns>
        Task<TApplication> FindByLogoutRedirectUri(string url, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the client type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client type of the application (by default, "public").
        /// </returns>
        Task<string> GetClientTypeAsync(TApplication application, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the display name associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the application.
        /// </returns>
        Task<string> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the hashed secret associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the hashed secret associated with the application.
        /// </returns>
        Task<string> GetHashedSecretAsync(TApplication application, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the callback address associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the redirect_uri associated with the application.
        /// </returns>
        Task<string> GetRedirectUriAsync(TApplication application, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the token identifiers associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the application.
        /// </returns>
        Task<IEnumerable<string>> GetTokensAsync(TApplication application, CancellationToken cancellationToken);
    }
}