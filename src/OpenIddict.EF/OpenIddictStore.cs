﻿using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using OpenIddict.Models;
using System.Linq;

namespace OpenIddict {
    public class OpenIddictStore<TUser, TApplication, TRole, TKey, TScope> : UserStore<TUser, TRole, OpenIddictContext<TUser, TApplication, TRole, TKey, TScope>, TKey>, IOpenIddictStore<TUser, TApplication, TScope>
        where TUser : IdentityUser<TKey>
        where TApplication : Application
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TScope : Scope {
        public OpenIddictStore(OpenIddictContext<TUser, TApplication, TRole, TKey, TScope> context)
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

        public virtual async Task<IEnumerable<TScope>> GetScopesByApplicationAsync(TApplication application, CancellationToken cancellationToken) {
            return await Context.Scopes.Where(s => s.ApplicationID == application.ApplicationID).ToListAsync(cancellationToken);
        }

        public virtual Task<string> GetScopeDisplayNameAsync(TScope scope, CancellationToken cancellationToken) {
            if (scope == null) {
                throw new ArgumentNullException(nameof(scope));
            }

            return Task.FromResult(scope.DisplayName);
        }

        public virtual Task<string> GetScopeDescriptionAsync(TScope scope, CancellationToken cancellationToken) {
            if (scope == null) {
                throw new ArgumentNullException(nameof(scope));
            }

            return Task.FromResult(scope.Description);
        }

        public virtual Task<string> GetScopeIdAsync(TScope scope, CancellationToken cancellationToken) {
            if (scope == null) {
                throw new ArgumentNullException(nameof(scope));
            }

            return Task.FromResult(scope.ScopeID);
        }

        public async Task<IEnumerable<TScope>> GetAuthorizationRequesteScopesAsync(IEnumerable<string> requestScopes, CancellationToken cancellationToken) {
            // Note that scopes should be evalued in a case-sensitive way, as described here http://tools.ietf.org/html/rfc6749#section-3.3
            // so I'm using string.Equals to make this intent crystal clear.
            return await Context.Scopes.Where(s => requestScopes.Contains(s.ScopeID, StringComparer.Ordinal)).ToListAsync(cancellationToken);
        }
    }
}