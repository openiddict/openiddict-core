/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using OpenIddict.Server.Quartz;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
            if (configuration is null)
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
        public OpenIddictServerQuartzBuilder DisableAuthorizationPruning()
            => Configure(options => options.DisableAuthorizationPruning = true);

        /// <summary>
        /// Disables tokens pruning.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public OpenIddictServerQuartzBuilder DisableTokenPruning()
            => Configure(options => options.DisableTokenPruning = true);

        /// <summary>
        /// Sets the number of times a failed Quartz.NET job can be retried.
        /// </summary>
        /// <param name="count">The number of times a failed Quartz.NET job can be retried.</param>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public OpenIddictServerQuartzBuilder SetMaximumRefireCount(int count)
        {
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(count), SR.GetResourceString(SR.ID1278));
            }

            return Configure(options => options.MaximumRefireCount = count);
        }

        /// <summary>
        /// Sets the minimum lifespan authorizations must have to be pruned.
        /// </summary>
        /// <param name="lifespan">The minimum lifespan authorizations must have to be pruned.</param>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public OpenIddictServerQuartzBuilder SetMinimumAuthorizationLifespan(TimeSpan lifespan)
        {
            if (lifespan < TimeSpan.FromMinutes(10))
            {
                throw new ArgumentOutOfRangeException(nameof(lifespan), SR.GetResourceString(SR.ID1279));
            }

            return Configure(options => options.MinimumAuthorizationLifespan = lifespan);
        }

        /// <summary>
        /// Sets the minimum lifespan tokens must have to be pruned.
        /// </summary>
        /// <param name="lifespan">The minimum lifespan tokens must have to be pruned.</param>
        /// <returns>The <see cref="OpenIddictServerQuartzBuilder"/>.</returns>
        public OpenIddictServerQuartzBuilder SetMinimumTokenLifespan(TimeSpan lifespan)
        {
            if (lifespan < TimeSpan.FromMinutes(10))
            {
                throw new ArgumentOutOfRangeException(nameof(lifespan), SR.GetResourceString(SR.ID1279));
            }

            return Configure(options => options.MinimumTokenLifespan = lifespan);
        }

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
