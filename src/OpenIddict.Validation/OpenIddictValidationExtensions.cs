/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Validation;
using OpenIddict.Validation.Internal;

namespace Microsoft.Extensions.DependencyInjection
{
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

            builder.Services.TryAddScoped<OpenIddictValidationEventService>();

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

        /// <summary>
        /// Registers the OpenIddict validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="app">The application builder used to register middleware instances.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseOpenIddictValidation([NotNull] this IApplicationBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            var options = app.ApplicationServices.GetRequiredService<IOptions<OpenIddictValidationOptions>>().Value;
            if (options.Events == null || options.Events.GetType() != typeof(OpenIddictValidationProvider))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("OpenIddict can only be used with its built-in validation provider.")
                    .AppendLine("This error may indicate that 'OpenIddictValidationOptions.Events' was manually set.")
                    .Append("To execute custom request handling logic, consider registering an event handler using ")
                    .Append("the generic 'services.AddOpenIddict().AddValidation().AddEventHandler()' method.")
                    .ToString());
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = app.ApplicationServices.GetDataProtectionProvider();
            }

            if (options.UseReferenceTokens && options.AccessTokenFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    "OpenIdConnectServerHandler",
                    nameof(options.AccessTokenFormat),
                    nameof(options.UseReferenceTokens), "ASOS");

                options.AccessTokenFormat = new TicketDataFormat(protector);
            }

            return app.UseOAuthValidation(options);
        }
    }
}