/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Validation;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict validation services.
    /// </summary>
    public static class OpenIddictValidationExtensions
    {
        /// <summary>
        /// Registers the OpenIddict token validation services in the DI container.
        /// Note: the validation handler only works with the default token format
        /// or reference tokens and cannot be used with JWT tokens. To validate
        /// JWT tokens, use the JWT bearer handler shipping with ASP.NET Core.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictValidationBuilder"/>.</returns>
        public static OpenIddictValidationBuilder AddValidation([NotNull] this OpenIddictBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddAuthentication();
            builder.Services.AddLogging();
            builder.Services.AddOptions();

            builder.Services.TryAddScoped<IOpenIddictValidationEventDispatcher, OpenIddictValidationEventDispatcher>();
            builder.Services.TryAddScoped<OpenIddictValidationHandler>();
            builder.Services.TryAddScoped<OpenIddictValidationProvider>();

            // Register the options initializers used by the OAuth validation handler and OpenIddict.
            // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
            builder.Services.TryAddEnumerable(new[]
            {
                ServiceDescriptor.Singleton<IConfigureOptions<AuthenticationOptions>, OpenIddictValidationConfiguration>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<AuthenticationOptions>, OpenIddictValidationConfiguration>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationOptions>, OpenIddictValidationConfiguration>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationOptions>, OAuthValidationInitializer>()
            });

            return new OpenIddictValidationBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict token validation services in the DI container.
        /// Note: the validation handler only works with the default token format
        /// or reference tokens and cannot be used with JWT tokens. To validate
        /// JWT tokens, use the JWT bearer handler shipping with ASP.NET Core.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the validation services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddValidation(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] Action<OpenIddictValidationBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.AddValidation());

            return builder;
        }
    }
}