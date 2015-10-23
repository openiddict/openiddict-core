using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.OptionsModel;

namespace OpenIddict {
    public class OpenIddictManager<TUser, TApplication, TScope> : UserManager<TUser> where TUser : class where TApplication : class where TScope : class {
        public OpenIddictManager([NotNull] IServiceProvider services)
            : base(services: services,
                store: services.GetService<IOpenIddictStore<TUser, TApplication, TScope>>(),
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
        public virtual new IOpenIddictStore<TUser, TApplication, TScope> Store {
            get { return base.Store as IOpenIddictStore<TUser, TApplication, TScope>; }
        }

        public virtual Task<TApplication> FindApplicationByIdAsync(string identifier) {
            return Store.FindApplicationByIdAsync(identifier, Context.RequestAborted);
        }

        public virtual Task<TApplication> FindApplicationByLogoutRedirectUri(string url) {
            return Store.FindApplicationByLogoutRedirectUri(url, Context.RequestAborted);
        }

        public virtual Task<string> GetApplicationTypeAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetApplicationTypeAsync(application, Context.RequestAborted);
        }

        public virtual Task<string> GetDisplayNameAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetDisplayNameAsync(application, Context.RequestAborted);
        }

        public virtual Task<string> GetRedirectUriAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetRedirectUriAsync(application, Context.RequestAborted);
        }

        public virtual Task<bool> ValidateSecretAsync(TApplication application, string secret) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.ValidateSecretAsync(application, secret, Context.RequestAborted);
        }

        public virtual Task<IEnumerable<TScope>> GetScopesByApplicationAsync(TApplication application) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Store.GetScopesByApplicationAsync(application, Context.RequestAborted);
        }

        public virtual Task<IEnumerable<TScope>> GetAuthorizationRequesteScopesAsync(IEnumerable<string> requestScopes) {
            return Store.GetAuthorizationRequesteScopesAsync(requestScopes, Context.RequestAborted);
        }

        public virtual Task<string> GetScopeIdAsync(TScope scope) {
            if (scope == null) {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetScopeIdAsync(scope, Context.RequestAborted);
        }

        public virtual Task<string> GetScopeDisplayNameAsync(TScope scope) {
            if (scope == null) {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetScopeDisplayNameAsync(scope, Context.RequestAborted);
        }

        public virtual Task<string> GetScopeDescriptionAsync(TScope scope) {
            if (scope == null) {
                throw new ArgumentNullException(nameof(scope));
            }

            return Store.GetScopeDescriptionAsync(scope, Context.RequestAborted);
        }
    }
}