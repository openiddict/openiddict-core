/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;

namespace OpenIddict {
    /// <summary>
    /// Provides various settings needed to configure OpenIddict.
    /// </summary>
    public class OpenIddictOptions : OpenIdConnectServerOptions {
        public OpenIddictOptions() {
            // By default, disable the authorization and logout endpoints.
            AuthorizationEndpointPath = LogoutEndpointPath = PathString.Empty;

            // Use the same lifespan as the default security stamp
            // verification interval used by ASP.NET Core Identity.
            AccessTokenLifetime = TimeSpan.FromMinutes(30);
        }

        /// <summary>
        /// Gets or sets the distributed cache used by OpenIddict. If no cache is explicitly
        /// provided, the cache registered in the dependency injection container is used.
        /// </summary>
        public IDistributedCache Cache { get; set; }

        /// <summary>
        /// Gets the list of the OpenIddict modules registered in the application.
        /// </summary>
        public ICollection<OpenIddictModule> Modules { get; } = new List<OpenIddictModule>();
    }
}
