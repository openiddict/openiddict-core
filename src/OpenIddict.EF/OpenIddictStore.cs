using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using OpenIddict.Models;

namespace OpenIddict {
    public class OpenIddictStore<TUser, TApplication, TRole, TKey> : UserStore<TUser, TRole, OpenIddictContext<TUser, TApplication, TRole, TKey>, TKey>, IOpenIddictStore<TUser, TApplication>
        where TUser : IdentityUser<TKey>
        where TApplication : Application
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        public OpenIddictStore(OpenIddictContext<TUser, TApplication, TRole, TKey> context)
            : base(context) {
        }

        public virtual Task<TApplication> FindApplicationByIdAsync(string identifier, CancellationToken cancellationToken) {
            return Context.Applications.SingleOrDefaultAsync(application => application.ApplicationID == identifier, cancellationToken);
        }

        public virtual Task<TApplication> FindApplicationByLogoutRedirectUri(string url, CancellationToken cancellationToken) {
            return Context.Applications.SingleOrDefaultAsync(application => application.LogoutRedirectUri == url, cancellationToken);
        }

        public virtual Task<string> GetApplicationTypeAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            switch (application.Type) {
            case ApplicationType.Confidential:
                return Task.FromResult(OpenIddictConstants.ApplicationTypes.Confidential);

            case ApplicationType.Public:
                return Task.FromResult(OpenIddictConstants.ApplicationTypes.Public);

            default:
                throw new InvalidOperationException($"Unsupported application type ('{application.Type.ToString()}').");
            }
        }

        public virtual Task<string> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.DisplayName);
        }

        public virtual Task<string> GetRedirectUriAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.RedirectUri);
        }

        public virtual Task<bool> ValidateSecretAsync(TApplication application, string secret, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(string.Equals(application.Secret, secret, StringComparison.Ordinal));
        }
    }
}