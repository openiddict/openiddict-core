/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;

namespace OpenIddict.Infrastructure {
    public static class OpenIddictHelpers {
        /// <summary>
        /// Tries to find the given claim in the user claims.
        /// </summary>
        /// <typeparam name="TUser">The type of the User entity.</typeparam>
        /// <param name="manager">The user manager.</param>
        /// <param name="user">The user.</param>
        /// <param name="type">The claim type.</param>
        /// <returns>The claim value, or <c>null</c> if it cannot be found.</returns>
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
            return (from claim in await manager.GetClaimsAsync(user)
                    where string.Equals(claim.Type, type, StringComparison.OrdinalIgnoreCase)
                    select claim.Value).FirstOrDefault();
        }

        /// <summary>
        /// Determines whether an application is a confidential client.
        /// </summary>
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <param name="manager">The application manager.</param>
        /// <param name="application">The application.</param>
        /// <returns><c>true</c> if the application is a confidential client, <c>false</c> otherwise.</returns>
        public static async Task<bool> IsConfidentialAsync<TApplication>(
            [NotNull] this OpenIddictApplicationManager<TApplication> manager,
            [NotNull] TApplication application) where TApplication : class {
            if (manager == null) {
                throw new ArgumentNullException(nameof(manager));
            }

            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await manager.GetClientTypeAsync(application);

            return string.Equals(type, OpenIddictConstants.ClientTypes.Confidential, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Determines whether an application is a public client.
        /// </summary>
        /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
        /// <param name="manager">The application manager.</param>
        /// <param name="application">The application.</param>
        /// <returns><c>true</c> if the application is a public client, <c>false</c> otherwise.</returns>
        public static async Task<bool> IsPublicAsync<TApplication>(
            [NotNull] this OpenIddictApplicationManager<TApplication> manager,
            [NotNull] TApplication application) where TApplication : class {
            if (manager == null) {
                throw new ArgumentNullException(nameof(manager));
            }

            if (application == null) {
                throw new ArgumentNullException(nameof(application));
            }

            var type = await manager.GetClientTypeAsync(application);

            return string.Equals(type, OpenIddictConstants.ClientTypes.Public, StringComparison.OrdinalIgnoreCase);
        }
    }
}
