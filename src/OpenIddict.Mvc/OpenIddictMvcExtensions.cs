/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Mvc;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict MVC services.
    /// </summary>
    public static class OpenIddictMvcExtensions
    {
        /// <summary>
        /// Registers the ASP.NET Core MVC services used by OpenIddict.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictMvcBuilder"/>.</returns>
        public static OpenIddictMvcBuilder UseMvc([NotNull] this OpenIddictServerBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            // Register the options initializer used by the OpenIddict MVC binding/validation components.
            // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IConfigureOptions<MvcOptions>, OpenIddictMvcConfiguration>());

            return new OpenIddictMvcBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the ASP.NET Core MVC model binders used by OpenIddict.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the MVC services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public static OpenIddictServerBuilder UseMvc(
            [NotNull] this OpenIddictServerBuilder builder,
            [NotNull] Action<OpenIddictMvcBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.UseMvc());

            return builder;
        }
    }
}
