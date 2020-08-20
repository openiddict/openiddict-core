/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Net.Http;
using OpenIddict.Validation.SystemNetHttp;
using Polly;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict validation/System.Net.Http integration.
    /// </summary>
    public class OpenIddictValidationSystemNetHttpBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictValidationBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictValidationSystemNetHttpBuilder(IServiceCollection services)
            => Services = services ?? throw new ArgumentNullException(nameof(services));

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict validation/server integration configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationSystemNetHttpBuilder"/>.</returns>
        public OpenIddictValidationSystemNetHttpBuilder Configure(Action<OpenIddictValidationSystemNetHttpOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Replaces the default HTTP error policy used by the OpenIddict validation services.
        /// </summary>
        /// <param name="policy">The HTTP Polly error policy.</param>
        /// <returns>The <see cref="OpenIddictValidationSystemNetHttpBuilder"/>.</returns>
        public OpenIddictValidationSystemNetHttpBuilder SetHttpErrorPolicy(IAsyncPolicy<HttpResponseMessage> policy)
            => Configure(options => options.HttpErrorPolicy = policy);

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
