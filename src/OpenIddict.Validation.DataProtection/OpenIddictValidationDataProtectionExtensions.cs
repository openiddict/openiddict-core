/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Validation;
using OpenIddict.Validation.DataProtection;
using static OpenIddict.Validation.DataProtection.OpenIddictValidationDataProtectionHandlers;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict ASP.NET Core Data Protection validation services.
    /// </summary>
    public static class OpenIddictValidationDataProtectionExtensions
    {
        /// <summary>
        /// Registers the OpenIddict ASP.NET Core Data Protection validation services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public static OpenIddictValidationDataProtectionBuilder UseDataProtection([NotNull] this OpenIddictValidationBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddDataProtection();

            // Register the built-in validation event handlers used by the OpenIddict Data Protection components.
            // Note: the order used here is not important, as the actual order is set in the options.
            builder.Services.TryAdd(DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

            // Note: TryAddEnumerable() is used here to ensure the initializers are registered only once.
            builder.Services.TryAddEnumerable(new[]
            {
                ServiceDescriptor.Singleton<IConfigureOptions<OpenIddictValidationOptions>, OpenIddictValidationDataProtectionConfiguration>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationDataProtectionOptions>, OpenIddictValidationDataProtectionConfiguration>()
            });

            return new OpenIddictValidationDataProtectionBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict ASP.NET Core Data Protection validation services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the validation services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public static OpenIddictValidationBuilder UseDataProtection(
            [NotNull] this OpenIddictValidationBuilder builder,
            [NotNull] Action<OpenIddictValidationDataProtectionBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseDataProtection());

            return builder;
        }
    }
}
