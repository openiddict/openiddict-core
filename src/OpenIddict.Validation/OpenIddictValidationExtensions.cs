/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Models;
using OpenIddict.Validation;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Provides extension methods used to configure the
    /// validation middleware in an ASP.NET Core pipeline.
    /// </summary>
    public static class OpenIddictValidationExtensions
    {
        /// <summary>
        /// Adds a new instance of the OpenIddict validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOpenIddictValidation([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddOpenIddictValidation<OpenIddictToken>();
        }

        /// <summary>
        /// Adds a new instance of the OpenIddict validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOpenIddictValidation<TToken>([NotNull] this AuthenticationBuilder builder)
            where TToken : class
        {
            return builder.AddOpenIddictValidation<TToken>(options => { });
        }
        
        /// <summary>
        /// Adds a new instance of the OpenIddict validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the validation options.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOpenIddictValidation(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<OpenIddictValidationOptions> configuration)
        {
            return builder.AddOpenIddictValidation<OpenIddictToken>(configuration);
        }

        /// <summary>
        /// Adds a new instance of the OpenIddict validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <typeparam name="TToken">The type of the Token entity.</typeparam>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the validation options.</param>
        /// <returns>The authentication builder.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public static AuthenticationBuilder AddOpenIddictValidation<TToken>(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<OpenIddictValidationOptions> configuration)
            where TToken : class
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIddictValidationOptions>,
                                            OpenIddictValidationInitializer>());

            // Register the OpenIddict validation handler in the authentication options,
            // so it can be discovered by the default authentication handler provider.
            builder.Services.Configure<AuthenticationOptions>(options =>
            {
                // Note: similarly to Identity, OpenIddict should be registered only once.
                // To prevent multiple schemes from being registered, a check is made here.
                if (options.SchemeMap.ContainsKey(OpenIddictValidationDefaults.AuthenticationScheme))
                {
                    return;
                }

                options.AddScheme(OpenIddictValidationDefaults.AuthenticationScheme, scheme =>
                {
                    scheme.HandlerType = typeof(OpenIddictValidationHandler<TToken>);
                });
            });

            builder.Services.Configure(OpenIddictValidationDefaults.AuthenticationScheme, configuration);

            return builder;
        }
    }
}