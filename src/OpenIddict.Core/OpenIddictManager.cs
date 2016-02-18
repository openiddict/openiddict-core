using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenIddict {
    public class OpenIddictManager<TUser, TApplication> : UserManager<TUser> where TUser : class where TApplication : class {
        public OpenIddictManager(
            IOpenIddictStore<TUser, TApplication> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<TUser> passwordHasher,
            IEnumerable<IUserValidator<TUser>> userValidators,
            IEnumerable<IPasswordValidator<TUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<TUser>> logger)
            : base(store, optionsAccessor,
                   passwordHasher, userValidators,
                   passwordValidators, keyNormalizer,
                   errors, services, logger) {
            Context = services.GetService<IHttpContextAccessor>()?.HttpContext;
            Options = optionsAccessor.Value;
        }

        /// <summary>
        /// Gets the HTTP context associated with the current manager.
        /// </summary>
        public virtual HttpContext Context { get; }

        /// <summary>
        /// Gets the cancellation token used to abort async operations.
        /// </summary>
        public virtual CancellationToken CancellationToken => Context?.RequestAborted ?? CancellationToken.None;

        /// <summary>
        /// Gets the Identity options associated with the current manager.
        /// </summary>
        public virtual IdentityOptions Options { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        public virtual new IOpenIddictStore<TUser, TApplication> Store {
            get { return base.Store as IOpenIddictStore<TUser, TApplication>; }
        }

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

            // Resolve the username and the email address associated with the user.
            var username = await GetUserNameAsync(user);
            var email = await GetEmailAsync(user);

            // Only add the name claim if the "profile" scope was granted.
            if (scopes.Contains(OpenIdConnectConstants.Scopes.Profile)) {
                // Throw an exception if the username corresponds to the registered
                // email address and if the "email" scope has not been requested.
                if (!scopes.Contains(OpenIdConnectConstants.Scopes.Email) &&
                     string.Equals(username, email, StringComparison.OrdinalIgnoreCase)) {
                    throw new InvalidOperationException("The 'email' scope is required.");
                }

                identity.AddClaim(ClaimTypes.Name, username,
                    OpenIdConnectConstants.Destinations.AccessToken,
                    OpenIdConnectConstants.Destinations.IdentityToken);
            }

            // Only add the email address if the "email" scope was granted.
            if (scopes.Contains(OpenIdConnectConstants.Scopes.Email)) {
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
                var identifier = await GetSecurityStampAsync(user);

                if (!string.IsNullOrEmpty(identifier)) {
                    identity.AddClaim(Options.ClaimsIdentity.SecurityStampClaimType, identifier,
                        OpenIdConnectConstants.Destinations.AccessToken,
                        OpenIdConnectConstants.Destinations.IdentityToken);
                }
            }

            return identity;
        }

        public virtual Task<TApplication> FindApplicationByIdAsync(string identifier) {
            return Store.FindApplicationByIdAsync(identifier, CancellationToken);
        }

        public virtual Task<TApplication> FindApplicationByLogoutRedirectUri(string url) {
            return Store.FindApplicationByLogoutRedirectUri(url, CancellationToken);
        }

        public virtual async Task<string> FindClaimAsync(TUser user, string type) {
            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentNullException(nameof(type));
            }

            // Note: GetClaimsAsync will automatically throw an exception
            // if the underlying store doesn't support custom claims.

            return (from claim in await GetClaimsAsync(user)
                    where string.Equals(claim.Type, type, StringComparison.Ordinal)
                    select claim.Value).FirstOrDefault();
        }

        public virtual async Task<string> GetApplicationTypeAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await Store.GetApplicationTypeAsync(application, CancellationToken);

            // Ensure the application type returned by the store is supported by the manager.
            if (!string.Equals(type, OpenIddictConstants.ApplicationTypes.Confidential, StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(type, OpenIddictConstants.ApplicationTypes.Public, StringComparison.OrdinalIgnoreCase)) {
                throw new InvalidOperationException("Only 'confidential' or 'public' applications are " +
                                                    "supported by the default OpenIddict manager.");
            }

            return type;
        }

        public virtual Task<string> GetDisplayNameAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetDisplayNameAsync(application, CancellationToken);
        }

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

        public virtual async Task<bool> ValidateSecretAsync(TApplication application, string secret) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            if (!await this.IsConfidentialApplicationAsync(application)) {
                Logger.LogWarning("Client authentication cannot be enforced for non-confidential applications.");

                return false;
            }

            var hash = await Store.GetHashedSecretAsync(application, CancellationToken);
            if (string.IsNullOrEmpty(hash)) {
                Logger.LogError("Client authentication failed for {Client} because " +
                                "no client secret was associated with the application.");

                return false;
            }

            var hasher = new PasswordHasher<TApplication>();
            if (hasher.VerifyHashedPassword(application, hash, secret) == PasswordVerificationResult.Failed) {
                Logger.LogWarning("Client authentication failed for {Client}.", await GetDisplayNameAsync(application));

                return false;
            }

            return true;
        }
    }
}