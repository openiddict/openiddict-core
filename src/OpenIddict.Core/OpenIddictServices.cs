/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict {
    public class OpenIddictServices {
        public OpenIddictServices(IServiceCollection services) {
            Services = services;
        }

        /// <summary>
        /// Gets or sets the type corresponding to the Application entity.
        /// </summary>
        public Type ApplicationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Role entity.
        /// </summary>
        public Type RoleType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the User entity.
        /// </summary>
        public Type UserType { get; set; }

        /// <summary>
        /// Gets the services used by OpenIddict.
        /// </summary>
        public IServiceCollection Services { get; }
    }
}