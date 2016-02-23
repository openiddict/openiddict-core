using System;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;

namespace OpenIddict {
    public static class OpenIddictHelpers {
        public static async Task<bool> IsConfidentialApplicationAsync<TUser, TApplication>(
            [NotNull] this OpenIddictManager<TUser, TApplication> manager, [NotNull] TApplication application)
            where TUser : class
            where TApplication : class {
            if (manager == null) {
                throw new ArgumentNullException(nameof(manager));
            }

            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await manager.GetApplicationTypeAsync(application);

            return string.Equals(type, OpenIddictConstants.ApplicationTypes.Confidential, StringComparison.OrdinalIgnoreCase);
        }

        public static async Task<bool> IsPublicApplicationAsync<TUser, TApplication>(
            [NotNull] this OpenIddictManager<TUser, TApplication> manager, [NotNull] TApplication application)
            where TUser : class
            where TApplication : class {
            if (manager == null) {
                throw new ArgumentNullException(nameof(manager));
            }

            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await manager.GetApplicationTypeAsync(application);

            return string.Equals(type, OpenIddictConstants.ApplicationTypes.Public, StringComparison.OrdinalIgnoreCase);
        }

        public static async Task<string> FindClaimAsync<TUser>(
            [NotNull] this UserManager<TUser> manager,
            [NotNull] TUser user, [NotNull] string type) where TUser : class {
            if (manager == null) {
                throw new ArgumentNullException(nameof(manager));
            }

            if (user == null) {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrEmpty(type)) {
                throw new ArgumentNullException(nameof(type));
            }

            // Note: GetClaimsAsync will automatically throw an exception
            // if the underlying store doesn't support custom claims.

            var claims = await manager.GetClaimsAsync(user);
            if (claims.Count != 0) {
                return claims[0]?.Value;
            }

            return null;
        }
    }
}
