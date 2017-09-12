/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CryptoHelper;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Core
{
    /// <summary>
    /// Provides methods allowing to manage the applications stored in the store.
    /// </summary>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    public class OpenIddictApplicationManager<TApplication> where TApplication : class
    {
        public OpenIddictApplicationManager(
            [NotNull] IOpenIddictApplicationStore<TApplication> store,
            [NotNull] ILogger<OpenIddictApplicationManager<TApplication>> logger)
        {
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
        /// Gets the applications as a queryable source,
        /// if supported by the underlying store.
        /// </summary>
        public virtual IQueryable<TApplication> Applications => Store.Applications;

        /// <summary>
        /// Creates a new application.
        /// </summary>
        /// <param name="application">The application to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        public virtual Task<TApplication> CreateAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            return CreateAsync(application, /* secret: */ null, cancellationToken);
        }

        /// <summary>
        /// Creates a new application.
        /// Note: the default implementation automatically hashes the client
        /// secret before storing it in the database, for security reasons.
        /// </summary>
        /// <param name="application">The application to create.</param>
        /// <param name="secret">The client secret associated with the application, if applicable.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        public virtual async Task<TApplication> CreateAsync(
            [NotNull] TApplication application,
            [CanBeNull] string secret, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (!string.IsNullOrEmpty(await Store.GetClientSecretAsync(application, cancellationToken)))
            {
                throw new ArgumentException("The client secret hash cannot be directly set on the application entity.");
            }

            // If no client type was specified, assume it's a public application if no secret was provided.
            var type = await Store.GetClientTypeAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                await Store.SetClientTypeAsync(application, string.IsNullOrEmpty(secret) ?
                    OpenIddictConstants.ClientTypes.Public :
                    OpenIddictConstants.ClientTypes.Confidential, cancellationToken);
            }

            if (string.IsNullOrEmpty(secret))
            {
                // If the client is a confidential application, throw an
                // exception as the client secret is required in this case.
                if (string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("A client secret must be provided when creating a confidential application.");
                }

                await Store.SetClientSecretAsync(application, null, cancellationToken);
            }

            else
            {
                secret = await ObfuscateClientSecretAsync(secret, cancellationToken);
                await Store.SetClientSecretAsync(application, secret, cancellationToken);
            }

            await ValidateAsync(application, cancellationToken);

            return await Store.CreateAsync(application, cancellationToken);
        }

        /// <summary>
        /// Removes an existing application.
        /// </summary>
        /// <param name="application">The application to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual Task DeleteAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.DeleteAsync(application, cancellationToken);
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
        public virtual Task<TApplication> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
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
        public virtual Task<TApplication> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
        {
            return Store.FindByClientIdAsync(identifier, cancellationToken);
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified post_logout_redirect_uri.
        /// </summary>
        /// <param name="address">The post_logout_redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
        /// returns the client applications corresponding to the specified post_logout_redirect_uri.
        /// </returns>
        public virtual Task<TApplication[]> FindByLogoutRedirectUriAsync(string address, CancellationToken cancellationToken)
        {
            return Store.FindByLogoutRedirectUriAsync(address, cancellationToken);
        }

        /// <summary>
        /// Retrieves all the applications associated with the specified redirect_uri.
        /// </summary>
        /// <param name="address">The redirect_uri associated with the applications.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
        /// returns the client applications corresponding to the specified redirect_uri.
        /// </returns>
        public virtual Task<TApplication[]> FindByRedirectUriAsync(string address, CancellationToken cancellationToken)
        {
            return Store.FindByRedirectUriAsync(address, cancellationToken);
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
        public virtual async Task<string> GetClientTypeAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await Store.GetClientTypeAsync(application, cancellationToken);

            // Ensure the application type returned by the store is supported by the manager.
            if (!string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
            {
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
        public virtual Task<string> GetDisplayNameAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetDisplayNameAsync(application, cancellationToken);
        }

        /// <summary>
        /// Retrieves the unique identifier associated with an application.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the application.
        /// </returns>
        public virtual Task<string> GetIdAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetIdAsync(application, cancellationToken);
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
        public virtual Task<IEnumerable<string>> GetTokensAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetTokensAsync(application, cancellationToken);
        }

        /// <summary>
        /// Determines whether the specified application has a redirect_uri.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether a redirect_uri is registered.
        /// </returns>
        public virtual async Task<bool> HasRedirectUriAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return !string.IsNullOrEmpty(await Store.GetRedirectUriAsync(application, cancellationToken));
        }

        /// <summary>
        /// Determines whether the specified application has a client secret.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether a client secret is registered.
        /// </returns>
        public virtual async Task<bool> HasClientSecretAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return !string.IsNullOrEmpty(await Store.GetClientSecretAsync(application, cancellationToken));
        }

        /// <summary>
        /// Determines whether an application is a confidential client.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns><c>true</c> if the application is a confidential client, <c>false</c> otherwise.</returns>
        public async Task<bool> IsConfidentialAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await GetClientTypeAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
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
        public async Task<bool> IsPublicAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            // Assume client applications are public if their type is not explicitly set.
            var type = await GetClientTypeAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                return true;
            }

            return string.Equals(type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Updates an existing application.
        /// </summary>
        /// <param name="application">The application to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task UpdateAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            await ValidateAsync(application, cancellationToken);
            await Store.UpdateAsync(application, cancellationToken);
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
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public virtual async Task UpdateAsync([NotNull] TApplication application,
            [CanBeNull] string secret, CancellationToken cancellationToken)
        {
            if (application == null)
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
        /// Validates the specified post_logout_redirect_uri.
        /// </summary>
        /// <param name="address">The address that should be compared to the post_logout_redirect_uri stored in the database.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation, whose result
        /// returns a boolean indicating whether the post_logout_redirect_uri was valid.
        /// </returns>
        public virtual async Task<bool> ValidateLogoutRedirectUriAsync(string address, CancellationToken cancellationToken)
        {
            // Warning: SQL engines like Microsoft SQL Server are known to use case-insensitive lookups by default.
            // To ensure a case-sensitive comparison is used, string.Equals(Ordinal) is manually called here.
            foreach (var application in await Store.FindByLogoutRedirectUriAsync(address, cancellationToken))
            {
                // Note: the post_logout_redirect_uri must be compared using case-sensitive "Simple String Comparison".
                if (string.Equals(address, await Store.GetLogoutRedirectUriAsync(application, cancellationToken), StringComparison.Ordinal))
                {
                    return true;
                }
            }

            Logger.LogWarning("Client validation failed because '{PostLogoutRedirectUri}' " +
                              "was not a valid post_logout_redirect_uri.", address);

            return false;
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
        public virtual async Task<bool> ValidateRedirectUriAsync([NotNull] TApplication application, string address, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            // Note: the redirect_uri must be compared using case-sensitive "Simple String Comparison".
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest for more information.
            if (string.Equals(address, await Store.GetRedirectUriAsync(application, cancellationToken), StringComparison.Ordinal))
            {
                return true;
            }

            Logger.LogWarning("Client validation failed because '{RedirectUri}' was not a valid redirect_uri " +
                              "for '{Client}'.", address, await GetDisplayNameAsync(application, cancellationToken));

            return false;
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
        public virtual async Task<bool> ValidateClientSecretAsync([NotNull] TApplication application, string secret, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (!await IsConfidentialAsync(application, cancellationToken))
            {
                Logger.LogWarning("Client authentication cannot be enforced for non-confidential applications.");

                return false;
            }

            var value = await Store.GetClientSecretAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(value))
            {
                Logger.LogError("Client authentication failed for {Client} because " +
                                "no client secret was associated with the application.");

                return false;
            }

            if (!await ValidateClientSecretAsync(secret, value, cancellationToken))
            {
                Logger.LogWarning("Client authentication failed for {Client}.",
                    await GetDisplayNameAsync(application, cancellationToken));

                return false;
            }

            return true;
        }

        /// <summary>
        /// Validates the application to ensure it's in a consistent state.
        /// </summary>
        /// <param name="application">The application.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        protected virtual async Task ValidateAsync([NotNull] TApplication application, CancellationToken cancellationToken)
        {
            if (application == null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(await Store.GetClientIdAsync(application, cancellationToken)))
            {
                throw new ArgumentException("The client identifier cannot be null or empty.", nameof(application));
            }

            var type = await Store.GetClientTypeAsync(application, cancellationToken);
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The client type cannot be null or empty.", nameof(application));
            }

            // Ensure the application type is supported by the manager.
            if (!string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("Only 'confidential' or 'public' applications are " +
                                            "supported by the default application manager.", nameof(application));
            }

            var secret = await Store.GetClientSecretAsync(application, cancellationToken);

            // Ensure a client secret was specified if the client is a confidential application.
            if (string.IsNullOrEmpty(secret) &&
                string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("The client secret cannot be null or empty for a confidential application.", nameof(application));
            }

            // Ensure no client secret was specified if the client is a public application.
            else if (!string.IsNullOrEmpty(secret) &&
                      string.Equals(type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("A client secret cannot be associated with a public application.", nameof(application));
            }

            // When a redirect_uri is specified, ensure it is valid and spec-compliant.
            // See https://tools.ietf.org/html/rfc6749#section-3.1 for more information.
            var address = await Store.GetRedirectUriAsync(application, cancellationToken);
            if (!string.IsNullOrEmpty(address))
            {
                // Ensure the redirect_uri is a valid and absolute URL.
                if (!Uri.TryCreate(address, UriKind.Absolute, out Uri uri))
                {
                    throw new ArgumentException("The redirect_uri must be an absolute URL.");
                }

                // Ensure the redirect_uri doesn't contain a fragment.
                if (!string.IsNullOrEmpty(uri.Fragment))
                {
                    throw new ArgumentException("The redirect_uri cannot contain a fragment.");
                }
            }

            // When a post_logout_redirect_uri is specified, ensure it is valid.
            address = await Store.GetLogoutRedirectUriAsync(application, cancellationToken);
            if (!string.IsNullOrEmpty(address))
            {
                // Ensure the post_logout_redirect_uri is a valid and absolute URL.
                if (!Uri.TryCreate(address, UriKind.Absolute, out Uri uri))
                {
                    throw new ArgumentException("The post_logout_redirect_uri must be an absolute URL.");
                }

                // Ensure the post_logout_redirect_uri doesn't contain a fragment.
                if (!string.IsNullOrEmpty(uri.Fragment))
                {
                    throw new ArgumentException("The post_logout_redirect_uri cannot contain a fragment.");
                }
            }
        }

        /// <summary>
        /// Obfuscates the specified client secret so it can be safely stored in a database.
        /// By default, this method returns a complex hashed representation computed using PBKDF2.
        /// </summary>
        /// <param name="secret">The client secret.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        protected virtual Task<string> ObfuscateClientSecretAsync([NotNull] string secret, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException("The secret cannot be null or empty.", nameof(secret));
            }

            return Task.FromResult(Crypto.HashPassword(secret));
        }

        /// <summary>
        /// Validates the specified value to ensure it corresponds to the client secret.
        /// Note: when overriding this method, using a time-constant comparer is strongly recommended.
        /// </summary>
        /// <param name="secret">The client secret to compare to the value stored in the database.</param>
        /// <param name="comparand">The value stored in the database, which is usually a hashed representation of the secret.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether the specified value was valid.
        /// </returns>
        protected virtual Task<bool> ValidateClientSecretAsync(
            [NotNull] string secret, [NotNull] string comparand, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException("The secret cannot be null or empty.", nameof(secret));
            }

            if (string.IsNullOrEmpty(comparand))
            {
                throw new ArgumentException("The comparand cannot be null or empty.", nameof(comparand));
            }

            try
            {
                return Task.FromResult(Crypto.VerifyHashedPassword(comparand, secret));
            }

            catch (Exception exception)
            {
                Logger.LogWarning(exception, "An error occurred while trying to verify a client secret. " +
                                             "This may indicate that the hashed entry is corrupted or malformed.");

                return Task.FromResult(false);
            }
        }
    }
}