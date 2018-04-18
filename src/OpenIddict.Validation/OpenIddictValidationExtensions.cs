/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Text.Encodings.Web;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Validation;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIddictValidationExtensions
    {
        /// <summary>
        /// Registers the OpenIddict token validation services in the DI container.
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

            // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
            builder.Services.TryAddEnumerable(new[]
            {
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationOptions>,
                                            OpenIddictValidationInitializer>(),
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationOptions>,
                                            OAuthValidationInitializer>()
            });

            builder.Services.TryAddScoped(typeof(OpenIddictValidationHandler<>));
            builder.Services.TryAddScoped(provider =>
            {
                var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>()
                    .Get(OAuthValidationDefaults.AuthenticationScheme);

                if (options == null)
                {
                    throw new InvalidOperationException("The OpenIddict validation options cannot be resolved.");
                }

                if (options.UseReferenceTokens)
                {
                    if (options.TokenType == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .AppendLine("The entity types must be configured for the token validation services to work correctly.")
                            .Append("To configure the entities, use either 'services.AddOpenIddict().AddCore().UseDefaultModels()' ")
                            .Append("or 'services.AddOpenIddict().AddCore().UseCustomModels()'.")
                            .ToString());
                    }

                    var type = typeof(OpenIddictValidationHandler<>).MakeGenericType(options.TokenType);
                    return (OpenIddictValidationHandler) provider.GetService(type);
                }

                return new OpenIddictValidationHandler(
                    provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>(),
                    provider.GetRequiredService<ILoggerFactory>(),
                    provider.GetRequiredService<UrlEncoder>(),
                    provider.GetRequiredService<ISystemClock>());
            });

            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationOptions>,
                                            OAuthValidationInitializer>());

            // Register the OpenIddict validation handler in the authentication options,
            // so it can be discovered by the default authentication handler provider.
            builder.Services.Configure<AuthenticationOptions>(options =>
            {
                // Note: this method is guaranteed to be idempotent. To prevent multiple schemes from being
                // registered (which would result in an exception being thrown), a manual check is made here.
                if (options.SchemeMap.ContainsKey(OAuthValidationDefaults.AuthenticationScheme))
                {
                    return;
                }

                options.AddScheme(OAuthValidationDefaults.AuthenticationScheme, scheme =>
                {
                    scheme.HandlerType = typeof(OpenIddictValidationHandler);
                });
            });

            return new OpenIddictValidationBuilder(builder.Services);
        }

        /// <summary>
        /// Registers the OpenIddict token validation services in the DI container.
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