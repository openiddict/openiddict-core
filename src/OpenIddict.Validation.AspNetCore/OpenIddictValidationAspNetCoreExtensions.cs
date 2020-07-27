/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlerFilters;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreHandlers;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict validation services.
    /// </summary>
    public static class OpenIddictValidationAspNetCoreExtensions
    {
        /// <summary>
        /// Registers the OpenIddict validation services for ASP.NET Core in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationAspNetCoreBuilder"/>.</returns>
        public static OpenIddictValidationAspNetCoreBuilder UseAspNetCore(this OpenIddictValidationBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddAuthentication();

            builder.Services.TryAddScoped<OpenIddictValidationAspNetCoreHandler>();

            // Register the built-in event handlers used by the OpenIddict ASP.NET Core validation components.
            // Note: the order used here is not important, as the actual order is set in the options.
            builder.Services.TryAdd(DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

            // Register the built-in filters used by the default OpenIddict ASP.NET Core validation event handlers.
            builder.Services.TryAddSingleton<RequireHttpRequest>();

            // Register the option initializer used by the OpenIddict ASP.NET Core validation integration services.
            // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
            builder.Services.TryAddEnumerable(new[]
            {
                ServiceDescriptor.Singleton<IConfigureOptions<AuthenticationOptions>, OpenIddictValidationAspNetCoreConfiguration>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<AuthenticationOptions>, OpenIddictValidationAspNetCoreConfiguration>(),

                ServiceDescriptor.Singleton<IConfigureOptions<OpenIddictValidationOptions>, OpenIddictValidationAspNetCoreConfiguration>()
            });

            return new OpenIddictValidationAspNetCoreBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict validation services for ASP.NET Core in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the validation services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public static OpenIddictValidationBuilder UseAspNetCore(
            this OpenIddictValidationBuilder builder, Action<OpenIddictValidationAspNetCoreBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseAspNetCore());

            return builder;
        }
    }
}
