using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Models;

namespace OpenIddict {
    public class OpenIddictStore<TUser, TApplication, TContext, TKey> : IOpenIddictStore<TUser, TApplication>
        where TUser : IdentityUser<TKey>
        where TApplication : Application
        where TContext : DbContext
        where TKey : IEquatable<TKey> {
        public OpenIddictStore(TContext context) {
            Context = context;
        }

        /// <summary>
        /// Gets the database context associated with the current store.
        /// </summary>
        public virtual TContext Context { get; }

        public DbSet<TApplication> Applications {
            get { return Context.Set<TApplication>(); }
        }

        public virtual Task<TApplication> FindApplicationByIdAsync(string identifier, CancellationToken cancellationToken) {
            return Applications.SingleOrDefaultAsync(application => application.Id == identifier, cancellationToken);
        }

        public virtual Task<TApplication> FindApplicationByLogoutRedirectUri(string url, CancellationToken cancellationToken) {
            return Applications.SingleOrDefaultAsync(application => application.LogoutRedirectUri == url, cancellationToken);
        }

        public virtual Task<string> GetApplicationTypeAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.Type);
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

        public virtual Task<string> GetHashedSecretAsync(TApplication application, CancellationToken cancellationToken) {
            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            return Task.FromResult(application.Secret);
        }
    }
}