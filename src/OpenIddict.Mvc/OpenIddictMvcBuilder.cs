/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using OpenIddict.Mvc;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict MVC integration.
    /// </summary>
    public class OpenIddictMvcBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictMvcBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictMvcBuilder([NotNull] IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            Services = services;
        }

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict MVC configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictMvcBuilder"/>.</returns>
        public OpenIddictMvcBuilder Configure([NotNull] Action<OpenIddictMvcOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Configures the OpenIddict MVC binder to avoid throwing an exception
        /// when it is unable to bind <see cref="OpenIdConnectRequest"/>
        /// parameters (e.g because the endpoint is not an OpenID Connect endpoint).
        /// </summary>
        /// <returns>The <see cref="OpenIddictMvcBuilder"/>.</returns>
        public OpenIddictMvcBuilder DisableBindingExceptions()
            => Configure(options => options.DisableBindingExceptions = true);
    }
}
