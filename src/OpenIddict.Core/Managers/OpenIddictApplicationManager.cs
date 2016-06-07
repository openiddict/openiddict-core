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
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict {
    /// <summary>
    /// Provides methods allowing to manage the applications stored in the store.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    public class OpenIddictApplicationManager<TApplication> where TApplication : class {
        public OpenIddictApplicationManager(
            [NotNull] IServiceProvider services,
            [NotNull] IOpenIddictApplicationStore<TApplication> store,
            [NotNull] ILogger<OpenIddictApplicationManager<TApplication>> logger) {
            Context = services?.GetRequiredService<IHttpContextAccessor>()?.HttpContext;
            Store = store;
            Logger = logger;
        }

        /// <summary>
        /// Gets the HTTP context associated with the current manager.
        /// </summary>
        protected HttpContext Context { get; }

        /// <summary>
        /// Gets the cancellation token used to abort async operations.
        /// </summary>
        protected CancellationToken CancellationToken => Context?.RequestAborted ?? CancellationToken.None;

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
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        public virtual Task<string> CreateAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.CreateAsync(application, CancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the application.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client application corresponding to the identifier.
        /// </returns>
        public virtual Task<TApplication> FindByIdAsync(string identifier) {
            return Store.FindByIdAsync(identifier, CancellationToken);
        }

        /// <summary>
        /// Retrieves an application using its post_logout_redirect_uri.
        /// </summary>
        /// <param name="url">The post_logout_redirect_uri associated with the application.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
        /// returns the client application corresponding to the post_logout_redirect_uri.
        /// </returns>
        public virtual Task<TApplication> FindByLogoutRedirectUri(string url) {
            return Store.FindByLogoutRedirectUri(url, CancellationToken);
        }

        /// <summary>
        /// Retrieves the client type associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the client type of the application (by default, "public").
        /// </returns>
        public virtual async Task<string> GetClientTypeAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await Store.GetClientTypeAsync(application, CancellationToken);

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
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the display name associated with the application.
        /// </returns>
        public virtual Task<string> GetDisplayNameAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetDisplayNameAsync(application, CancellationToken);
        }

        /// <summary>
        /// Retrieves the token identifiers associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the application.
        /// </returns>
        public virtual Task<IEnumerable<string>> GetTokensAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetTokensAsync(application, CancellationToken);
        }

        /// <summary>
        /// Validates the redirect_uri associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="address">The address that should be compared to the redirect_uri stored in the database.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether the redirect_uri was valid.
        /// </returns>
        public virtual async Task<bool> ValidateRedirectUriAsync(TApplication application, string address) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            if (!string.Equals(address, await Store.GetRedirectUriAsync(application, CancellationToken), StringComparison.Ordinal)) {
                Logger.LogWarning("Client validation failed because {RedirectUri} was not a valid redirect_uri " +
                                  "for {Client}", address, await GetDisplayNameAsync(application));

                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates the client_secret associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="secret">The secret that should be compared to the client_secret stored in the database.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether the client secret was valid.
        /// </returns>
        public virtual async Task<bool> ValidateSecretAsync(TApplication application, string secret) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await GetClientTypeAsync(application);
            if (type != OpenIddictConstants.ClientTypes.Confidential) {
                Logger.LogWarning("Client authentication cannot be enforced for non-confidential applications.");

                return false;
            }

            var hash = await Store.GetHashedSecretAsync(application, CancellationToken);
            if (string.IsNullOrEmpty(hash)) {
                Logger.LogError("Client authentication failed for {Client} because " +
                                "no client secret was associated with the application.");

                return false;
            }

            if (!Crypto.VerifyHashedPassword(hash, secret)) {
                Logger.LogWarning("Client authentication failed for {Client}.", await GetDisplayNameAsync(application));

                return false;
            }

            return true;
        }
    }
}