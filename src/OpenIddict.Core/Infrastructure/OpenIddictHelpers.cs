/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using JetBrains.Annotations;

namespace OpenIddict.Infrastructure {
    public static class OpenIddictHelpers {
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
