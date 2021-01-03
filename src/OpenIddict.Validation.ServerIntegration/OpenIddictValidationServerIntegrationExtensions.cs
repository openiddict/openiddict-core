/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Validation;
using OpenIddict.Validation.ServerIntegration;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict validation/server integration services.
    /// </summary>
    public static class OpenIddictValidationServerIntegrationExtensions
    {
        /// <summary>
        /// Registers the OpenIddict validation/server integration services in the DI container
        /// and automatically imports the configuration from the local OpenIddict server.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public static OpenIddictValidationServerIntegrationBuilder UseLocalServer(this OpenIddictValidationBuilder builder)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Note: TryAddEnumerable() is used here to ensure the initializers are registered only once.
            builder.Services.TryAddEnumerable(new[]
            {
                ServiceDescriptor.Singleton<IConfigureOptions<OpenIddictValidationOptions>, OpenIddictValidationServerIntegrationConfiguration>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationOptions>, OpenIddictValidationServerIntegrationConfiguration>()
            });

            return new OpenIddictValidationServerIntegrationBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict validation/server integration services in the DI container
        /// and automatically imports the configuration from the local OpenIddict server.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the validation services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictValidationBuilder UseLocalServer(
            this OpenIddictValidationBuilder builder, Action<OpenIddictValidationServerIntegrationBuilder> configuration)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration is null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseLocalServer());

            return builder;
        }
    }
}
