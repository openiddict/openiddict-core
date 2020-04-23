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
using OpenIddict.Server;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes extensions allowing to register the OpenIddict server services.
    /// </summary>
    public static class OpenIddictServerExtensions
    {
        /// <summary>
        /// Registers the OpenIddict token server services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public static OpenIddictServerBuilder AddServer([NotNull] this OpenIddictBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddLogging();
            builder.Services.AddOptions();

            builder.Services.TryAddScoped<IOpenIddictServerProvider, OpenIddictServerProvider>();

            // Register the built-in server event handlers used by the OpenIddict server components.
            // Note: the order used here is not important, as the actual order is set in the options.
            builder.Services.TryAdd(DefaultHandlers.Select(descriptor => descriptor.ServiceDescriptor));

            // Register the built-in filters used by the default OpenIddict server event handlers.
            builder.Services.TryAddSingleton<RequireAccessTokenIncluded>();
            builder.Services.TryAddSingleton<RequireAuthorizationCodeIncluded>();
            builder.Services.TryAddSingleton<RequireAuthorizationStorageEnabled>();
            builder.Services.TryAddSingleton<RequireClientIdParameter>();
            builder.Services.TryAddSingleton<RequireDegradedModeDisabled>();
            builder.Services.TryAddSingleton<RequireDeviceCodeIncluded>();
            builder.Services.TryAddSingleton<RequireEndpointPermissionsEnabled>();
            builder.Services.TryAddSingleton<RequireGrantTypePermissionsEnabled>();
            builder.Services.TryAddSingleton<RequireIdentityTokenIncluded>();
            builder.Services.TryAddSingleton<RequirePostLogoutRedirectUriParameter>();
            builder.Services.TryAddSingleton<RequireReferenceTokensEnabled>();
            builder.Services.TryAddSingleton<RequireRefreshTokenIncluded>();
            builder.Services.TryAddSingleton<RequireRollingTokensDisabled>();
            builder.Services.TryAddSingleton<RequireRollingTokensEnabled>();
            builder.Services.TryAddSingleton<RequireSlidingExpirationEnabled>();
            builder.Services.TryAddSingleton<RequireScopePermissionsEnabled>();
            builder.Services.TryAddSingleton<RequireScopeValidationEnabled>();
            builder.Services.TryAddSingleton<RequireTokenStorageEnabled>();
            builder.Services.TryAddSingleton<RequireUserCodeIncluded>();

            // Note: TryAddEnumerable() is used here to ensure the initializer is registered only once.
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<
                IPostConfigureOptions<OpenIddictServerOptions>, OpenIddictServerConfiguration>());

            return new OpenIddictServerBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict token server services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the server services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddServer(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] Action<OpenIddictServerBuilder> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            configuration(builder.AddServer());

            return builder;
        }
    }
}
