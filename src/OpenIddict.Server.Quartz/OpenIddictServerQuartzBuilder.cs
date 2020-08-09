/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using OpenIddict.Server.Quartz;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure
    /// the OpenIddict server Quartz.NET integration.
    /// </summary>
    public class OpenIddictServerQuartzBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictServerQuartzBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictServerQuartzBuilder(IServiceCollection services)
            => Services = services ?? throw new ArgumentNullException(nameof(services));

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict server Quartz.NET configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public OpenIddictServerQuartzBuilder Configure(Action<OpenIddictServerQuartzOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Disables authorizations pruning.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public OpenIddictServerQuartzBuilder DisableAuthorizationsPruning()
            => Configure(options => options.DisableAuthorizationsPruning = true);

        /// <summary>
        /// Disables tokens pruning.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public OpenIddictServerQuartzBuilder DisableTokensPruning()
            => Configure(options => options.DisableTokensPruning = true);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(object? obj) => base.Equals(obj);

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode() => base.GetHashCode();

        /// <inheritdoc/>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override string? ToString() => base.ToString();
    }
}
