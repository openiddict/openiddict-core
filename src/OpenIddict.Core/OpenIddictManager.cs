using System;
using System.Linq;
using System.Threading.Tasks;
using CryptoHelper;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.OptionsModel;

namespace OpenIddict {
    public class OpenIddictManager<TUser, TApplication> : UserManager<TUser> where TUser : class where TApplication : class {
        public OpenIddictManager([NotNull] IServiceProvider services)
            : base(services: services,
                   store: services.GetService<IOpenIddictStore<TUser, TApplication>>(),
                   optionsAccessor: services.GetService<IOptions<IdentityOptions>>(),
                   passwordHasher: services.GetService<IPasswordHasher<TUser>>(),
                   userValidators: services.GetServices<IUserValidator<TUser>>(),
                   passwordValidators: services.GetServices<IPasswordValidator<TUser>>(),
                   keyNormalizer: services.GetService<ILookupNormalizer>(),
                   errors: services.GetService<IdentityErrorDescriber>(),
                   logger: services.GetService<ILogger<UserManager<TUser>>>(),
                   contextAccessor: services.GetService<IHttpContextAccessor>()) {
            Context = services.GetRequiredService<IHttpContextAccessor>().HttpContext;
        }

        /// <summary>
        /// Gets the HTTP context associated with the current manager.
        /// </summary>
        public virtual HttpContext Context { get; }

        /// <summary>
        /// Gets the store associated with the current manager.
        /// </summary>
        public virtual new IOpenIddictStore<TUser, TApplication> Store {
            get { return base.Store as IOpenIddictStore<TUser, TApplication>; }
        }

        public virtual Task<TApplication> FindApplicationByIdAsync(string identifier) {
            return Store.FindApplicationByIdAsync(identifier, Context.RequestAborted);
        }

        public virtual Task<TApplication> FindApplicationByLogoutRedirectUri(string url) {
            return Store.FindApplicationByLogoutRedirectUri(url, Context.RequestAborted);
        }

        public virtual async Task<string> FindClaimAsync(TUser user, string type) {
            return (from claim in await GetClaimsAsync(user)
                    where string.Equals(claim.Type, type, StringComparison.Ordinal)
                    select claim.Value).FirstOrDefault();
        }

        public virtual async Task<string> GetApplicationTypeAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await Store.GetApplicationTypeAsync(application, Context.RequestAborted);

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

            return Store.GetDisplayNameAsync(application, Context.RequestAborted);
        }

        public virtual async Task<bool> ValidateRedirectUriAsync(TApplication application, string address) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            if (!string.Equals(address, await Store.GetRedirectUriAsync(application, Context.RequestAborted), StringComparison.Ordinal)) {
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

            var type = await GetApplicationTypeAsync(application);
            if (!string.Equals(type, OpenIddictConstants.ApplicationTypes.Confidential, StringComparison.OrdinalIgnoreCase)) {
                Logger.LogWarning("Client authentication cannot be enforced for non-confidential applications.");

                return false;
            }

            var hash = await Store.GetHashedSecretAsync(application, Context.RequestAborted);
            if (!Crypto.VerifyHashedPassword(hash, secret)) {
                Logger.LogWarning("Client authentication failed for {Client}.", await GetDisplayNameAsync(application));

                return false;
            }

            return true;
        }
    }
}