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
    }
}
