/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CryptoHelper;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Core {
    /// <summary>
    /// Provides methods allowing to manage the applications stored in the store.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    public class OpenIddictApplicationManager<TApplication> where TApplication : class {
        public OpenIddictApplicationManager(
            [NotNull] IOpenIddictApplicationStore<TApplication> store,
            [NotNull] ILogger<OpenIddictApplicationManager<TApplication>> logger) {
            Store = store;
            Logger = logger;
        }

        /// <summary>
        /// Gets the logger associated with the current manager.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected IOpenIddictApplicationStore<TApplication> Store { get; }

        /// <summary>
        /// Creates a new application.
        /// </summary>
        /// <param name="application">The application to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        public virtual Task<string> CreateAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.CreateAsync(application, cancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual Task<TApplication> FindByIdAsync(string identifier, CancellationToken cancellationToken) {
            return Store.FindByIdAsync(identifier, cancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its client identifier.
        /// </summary>
        /// <param name="identifier">The client identifier associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual Task<TApplication> FindByClientIdAsync(string identifier, CancellationToken cancellationToken) {
            return Store.FindByClientIdAsync(identifier, cancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its post_logout_redirect_uri.
        /// </summary>
        /// <param name="url">The post_logout_redirect_uri associated with the application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
        /// returns the client application corresponding to the post_logout_redirect_uri.
        /// </returns>
        public virtual Task<TApplication> FindByLogoutRedirectUri(string url, CancellationToken cancellationToken) {
            return Store.FindByLogoutRedirectUri(url, cancellationToken);
        }

        /// <summary>
        /// Retrieves the client type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client type of the application (by default, "public").
        /// </returns>
        public virtual async Task<string> GetClientTypeAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await Store.GetClientTypeAsync(application, cancellationToken);

            // Ensure the application type returned by the store is supported by the manager.
            if (!string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase)) {
                throw new InvalidOperationException("Only 'confidential' or 'public' applications are " +
                                                    "supported by the default application manager.");
            }

            return type;
        }

        /// <summary>
        /// Retrieves the display name associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the application.
        /// </returns>
        public virtual Task<string> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetDisplayNameAsync(application, cancellationToken);
        }

        /// <summary>
        /// Retrieves the token identifiers associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the application.
        /// </returns>
        public virtual Task<IEnumerable<string>> GetTokensAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetTokensAsync(application, cancellationToken);
        }
        /// <summary>
        /// Determines whether an application is a confidential client.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the application is a confidential client, <c>false</c> otherwise.</returns>
        public async Task<bool> IsConfidentialAsync([NotNull] TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await GetClientTypeAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(type)) {
                return false;
            }

            return string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether an application is a public client.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the application is a public client, <c>false</c> otherwise.</returns>
        public async Task<bool> IsPublicAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            // Assume client applications are public if their type is not explicitly set.
            var type = await GetClientTypeAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(type)) {
                return true;
            }

            return string.Equals(type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Validates the redirect_uri associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="address">The address that should be compared to the redirect_uri stored in the database.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether the redirect_uri was valid.
        /// </returns>
        public virtual async Task<bool> ValidateRedirectUriAsync(TApplication application, string address, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            if (!string.Equals(address, await Store.GetRedirectUriAsync(application, cancellationToken), StringComparison.Ordinal)) {
                Logger.LogWarning("Client validation failed because {RedirectUri} was not a valid redirect_uri " +
                                  "for {Client}", address, await GetDisplayNameAsync(application, cancellationToken));

                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates the client_secret associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="secret">The secret that should be compared to the client_secret stored in the database.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether the client secret was valid.
        /// </returns>
        public virtual async Task<bool> ValidateSecretAsync(TApplication application, string secret, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            if (!await IsConfidentialAsync(application, cancellationToken)) {
                Logger.LogWarning("Client authentication cannot be enforced for non-confidential applications.");

                return false;
            }

            var hash = await Store.GetHashedSecretAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(hash)) {
                Logger.LogError("Client authentication failed for {Client} because " +
                                "no client secret was associated with the application.");

                return false;
            }

            if (!Crypto.VerifyHashedPassword(hash, secret)) {
                Logger.LogWarning("Client authentication failed for {Client}.",
                    await GetDisplayNameAsync(application, cancellationToken));

                return false;
            }

            return true;
        }
    }
}