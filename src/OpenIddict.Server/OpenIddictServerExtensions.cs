/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Microsoft.Extensions.DependencyInjection
{
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

            builder.Services.AddAuthentication();

            builder.Services.TryAddScoped<OpenIddictServerHandler>();
            builder.Services.TryAddScoped(provider =>
            {
                InvalidOperationException CreateException()
                    => new InvalidOperationException(new StringBuilder()
                        .AppendLine("The core services must be registered when enabling the server handler.")
                        .Append("To register the OpenIddict core services, use 'services.AddOpenIddict().AddCore()'.")
                        .ToString());

                return new OpenIddictServerProvider(
                    provider.GetRequiredService<ILogger<OpenIddictServerProvider>>(),
                    provider.GetService<IOpenIddictApplicationManager>() ?? throw CreateException(),
                    provider.GetService<IOpenIddictAuthorizationManager>() ?? throw CreateException(),
                    provider.GetService<IOpenIddictScopeManager>() ?? throw CreateException(),
                    provider.GetService<IOpenIddictTokenManager>() ?? throw CreateException());
            });

            // Register the options initializers used by the OpenID Connect server handler and OpenIddict.
            // Note: TryAddEnumerable() is used here to ensure the initializers are only registered once.
            builder.Services.TryAddEnumerable(new[]
            {
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictServerOptions>, OpenIddictServerInitializer>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictServerOptions>, OpenIdConnectServerInitializer>()
            });

            // Register the OpenID Connect server handler in the authentication options,
            // so it can be discovered by the default authentication handler provider.
            builder.Services.Configure<AuthenticationOptions>(options =>
            {
                // Note: this method is guaranteed to be idempotent. To prevent multiple schemes from being
                // registered (which would result in an exception being thrown), a manual check is made here.
                if (options.SchemeMap.ContainsKey(OpenIddictServerDefaults.AuthenticationScheme))
                {
                    return;
                }

                options.AddScheme(OpenIddictServerDefaults.AuthenticationScheme, scheme =>
                {
                    scheme.HandlerType = typeof(OpenIddictServerHandler);
                });
            });

            return new OpenIddictServerBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict token server services in the DI container.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The configuration delegate used to configure the server services.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
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
