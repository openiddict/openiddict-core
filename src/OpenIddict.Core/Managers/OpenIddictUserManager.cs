/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict {
    /// <summary>
    /// Provides methods allowing to manage the users stored in the store.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    public class OpenIddictUserManager<TUser> : UserManager<TUser> where TUser : class {
        public OpenIddictUserManager(
            [NotNull] IServiceProvider services,
            [NotNull] IOpenIddictUserStore<TUser> store,
            [NotNull] IOptions<IdentityOptions> options,
            [NotNull] ILogger<OpenIddictUserManager<TUser>> logger,
            [NotNull] IPasswordHasher<TUser> hasher,
            [NotNull] IEnumerable<IUserValidator<TUser>> userValidators,
            [NotNull] IEnumerable<IPasswordValidator<TUser>> passwordValidators,
            [NotNull] ILookupNormalizer keyNormalizer,
            [NotNull] IdentityErrorDescriber errors)
            : base(store, options, hasher, userValidators, passwordValidators, keyNormalizer, errors, services, logger) {
            Context = services?.GetRequiredService<IHttpContextAccessor>()?.HttpContext;
            Logger = logger;
            Options = options.Value;
            Store = store;
        }

        /// <summary>
        /// Gets the cancellation token used to abort async operations.
        /// </summary>
        protected CancellationToken CancellationToken => Context?.RequestAborted ?? CancellationToken.None;

        /// <summary>
        /// Gets the HTTP context associated with the current manager.
        /// </summary>
        protected HttpContext Context { get; }

        /// <summary>
        /// Gets the identity options.
        /// </summary>
        protected IdentityOptions Options { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected new IOpenIddictUserStore<TUser> Store { get; }

        /// <summary>
        /// Creates a new <see cref="ClaimsIdentity"/> used to create new tokens.
        /// </summary>
        /// <param name="user">The user corresponding to the identity.</param>
        /// <param name="scopes">The scopes granted by the resource owner.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the <see cref="ClaimsIdentity"/> corresponding to the user.
        /// </returns>
        public virtual async Task<ClaimsIdentity> CreateIdentityAsync(TUser user, IEnumerable<string> scopes) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (scopes == null) {
                throw new ArgumentNullException(nameof(scopes));
            }

            var identity = new ClaimsIdentity(
                OpenIdConnectServerDefaults.AuthenticationScheme,
                Options.ClaimsIdentity.UserNameClaimType,
                Options.ClaimsIdentity.RoleClaimType);

            // Note: the name identifier is always included in both identity and
            // access tokens, even if an explicit destination is not specified.
            identity.AddClaim(ClaimTypes.NameIdentifier, await GetUserIdAsync(user));

            // Only add the name claim if the "profile" scope was granted.
            if (scopes.Contains(OpenIdConnectConstants.Scopes.Profile)) {
                var username = await GetUserNameAsync(user);

                identity.AddClaim(ClaimTypes.Name, username,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);
            }

            // Only add the email address if the "email" scope was granted.
            if (SupportsUserEmail && scopes.Contains(OpenIdConnectConstants.Scopes.Email)) {
                var email = await GetEmailAsync(user);

                identity.AddClaim(ClaimTypes.Email, email,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);
            }

            if (SupportsUserRole && scopes.Contains(OpenIddictConstants.Scopes.Roles)) {
                foreach (var role in await GetRolesAsync(user)) {
                    identity.AddClaim(identity.RoleClaimType, role,
                        OpenIdConnectConstants.Destinations.AccessToken,
                        OpenIdConnectConstants.Destinations.IdentityToken);
                }
            }

            if (SupportsUserSecurityStamp) {
                var stamp = await GetSecurityStampAsync(user);

                if (!string.IsNullOrEmpty(stamp)) {
                    identity.AddClaim(Options.ClaimsIdentity.SecurityStampClaimType, stamp,
                        OpenIdConnectConstants.Destinations.AccessToken,
                        OpenIdConnectConstants.Destinations.IdentityToken);
                }
            }

            return identity;
        }

        /// <summary>
        /// Creates a new token associated with the given user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="type">The token type.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        public virtual Task<string> CreateTokenAsync(TUser user, string type) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentException("The token type cannot be null or empty.", nameof(type));
            }

            return Store.CreateTokenAsync(user, type, CancellationToken);
        }

        /// <summary>
        /// Creates a new token associated with the given user and
        /// attached to the tokens issued to the specified client.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="client">The application.</param>
        /// <param name="type">The token type.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        public virtual Task<string> CreateTokenAsync(TUser user, string client, string type) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentException("The token type cannot be null or empty.", nameof(type));
            }

            return Store.CreateTokenAsync(user, client, type, CancellationToken);
        }

        /// <summary>
        /// Retrieves the token identifiers associated with a user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the user.
        /// </returns>
        public virtual Task<IEnumerable<string>> GetTokensAsync(TUser user) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            return Store.GetTokensAsync(user, CancellationToken);
        }
    }
}