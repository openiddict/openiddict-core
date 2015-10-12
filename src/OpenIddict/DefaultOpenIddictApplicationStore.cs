using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using OpenIddict.Models;

namespace OpenIddict {
    public class DefaultOpenIddictApplicationStore<TUser, TRole, TKey> : IOpenIddictApplicationStore
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey> {
        private readonly OpenIddictContext<TUser, TRole, TKey> _context;

        public DefaultOpenIddictApplicationStore(OpenIddictContext<TUser, TRole, TKey> context) {
            _context = context;
        }

        public Task<Application> FindApplicationByIdAsync(string applicationId, CancellationToken cancellationToken) {
            return _context.Applications.SingleOrDefaultAsync(application => application.ApplicationID == applicationId, cancellationToken);
        }

        public Task<Application> FindApplicationByLogoutRedirectUri(string logoutUri, CancellationToken cancellationToken) {
            return _context.Applications.SingleOrDefaultAsync(application => application.LogoutRedirectUri == logoutUri, cancellationToken);
        }
    }

    public class DefaultOpenIddictApplicationStore<TUser> : DefaultOpenIddictApplicationStore<TUser, IdentityRole, string>
        where TUser : IdentityUser<string> {
        public DefaultOpenIddictApplicationStore(OpenIddictContext<TUser, IdentityRole, string> context)
            : base(context) {
        }
    }

    public interface IOpenIddictApplicationStore {
        Task<Application> FindApplicationByIdAsync(string applicationId, CancellationToken cancellationToken);

        Task<Application> FindApplicationByLogoutRedirectUri(string logoutUri, CancellationToken cancellationToken);

        // add create/delete/update methods??
    }
}