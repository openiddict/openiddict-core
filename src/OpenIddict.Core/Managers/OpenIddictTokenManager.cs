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
    /// Provides methods allowing to manage the tokens stored in the store.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    public class OpenIddictTokenManager<TToken, TUser> where TToken : class where TUser : class {
        public OpenIddictTokenManager(
            [NotNull] IServiceProvider services,
            [NotNull] IOpenIddictTokenStore<TToken> store,
            [NotNull] UserManager<TUser> users,
            [NotNull] IOptions<IdentityOptions> options,
            [NotNull] ILogger<OpenIddictTokenManager<TToken, TUser>> logger) {
            Context = services?.GetRequiredService<IHttpContextAccessor>()?.HttpContext;
            Logger = logger;
            Options = options.Value;
            Store = store;
            Users = users;
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
        /// Gets the logger associated with the current manager.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the identity options.
        /// </summary>
        protected IdentityOptions Options { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        protected IOpenIddictTokenStore<TToken> Store { get; }

        /// <summary>
        /// Gets the user manager.
        /// </summary>
        protected UserManager<TUser> Users { get; }

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
            identity.AddClaim(ClaimTypes.NameIdentifier, await Users.GetUserIdAsync(user));

            // Resolve the email address associated with the user if the underlying store supports it.
            var email = Users.SupportsUserEmail ? await Users.GetEmailAsync(user) : null;

            // Only add the name claim if the "profile" scope was granted.
            if (scopes.Contains(OpenIdConnectConstants.Scopes.Profile)) {
                var username = await Users.GetUserNameAsync(user);

                // Throw an exception if the username corresponds to the registered
                // email address and if the "email" scope has not been requested.
                if (!scopes.Contains(OpenIdConnectConstants.Scopes.Email) &&
                    !string.IsNullOrEmpty(email) &&
                     string.Equals(username, email, StringComparison.OrdinalIgnoreCase)) {
                    throw new InvalidOperationException("The 'email' scope is required.");
                }

                identity.AddClaim(ClaimTypes.Name, username,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);
            }

            // Only add the email address if the "email" scope was granted.
            if (!string.IsNullOrEmpty(email) && scopes.Contains(OpenIdConnectConstants.Scopes.Email)) {
                identity.AddClaim(ClaimTypes.Email, email,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);
            }

            if (Users.SupportsUserRole && scopes.Contains(OpenIddictConstants.Scopes.Roles)) {
                foreach (var role in await Users.GetRolesAsync(user)) {
                    identity.AddClaim(identity.RoleClaimType, role,
                        OpenIdConnectConstants.Destinations.AccessToken,
                        OpenIdConnectConstants.Destinations.IdentityToken);
                }
            }

            if (Users.SupportsUserSecurityStamp) {
                var stamp = await Users.GetSecurityStampAsync(user);

                if (!string.IsNullOrEmpty(stamp)) {
                    identity.AddClaim(Options.ClaimsIdentity.SecurityStampClaimType, stamp,
                        OpenIdConnectConstants.Destinations.AccessToken,
                        OpenIdConnectConstants.Destinations.IdentityToken);
                }
            }

            return identity;
        }

        /// <summary>
        /// Creates a new token, defined by a unique identifier and a token type.
        /// </summary>
        /// <param name="type">The token type.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        public virtual Task<string> CreateAsync(string type) {
            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentException("The token type cannot be null or empty", nameof(type));
            }

            return Store.CreateAsync(type, CancellationToken);
        }

        /// <summary>
        /// Retrieves a token using its unique identifier.
        /// </summary>
        /// <param name="identifier">The unique identifier associated with the token.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the token corresponding to the unique identifier.
        /// </returns>
        public virtual Task<TToken> FindByIdAsync(string identifier) {
            if (string.IsNullOrEmpty(identifier)) {
                throw new ArgumentException("The identifier cannot be null or empty", nameof(identifier));
            }

            return Store.FindByIdAsync(identifier, CancellationToken);
        }

        /// <summary>
        /// Revokes a token.
        /// </summary>
        /// <param name="token">The token to revoke.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public virtual Task RevokeAsync(TToken token) {
            if (token == null) {
                throw new ArgumentNullException(nameof(token));
            }

            return Store.RevokeAsync(token, CancellationToken);
        }
    }
}