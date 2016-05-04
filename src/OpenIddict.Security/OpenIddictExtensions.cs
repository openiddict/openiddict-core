/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Cors.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using NWebsec.AspNetCore.Middleware;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        /// <summary>
        /// Registers the NWebsec module using the default Content Security Policy.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddNWebsec([NotNull] this OpenIddictBuilder builder) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddNWebsec(options => {
                options.DefaultSources(directive => directive.Self())
                       .ImageSources(directive => directive.Self())
                       .ScriptSources(directive => directive.Self())
                       .StyleSources(directive => directive.Self());
            });
        }

        /// <summary>
        /// Registers the NWebsec module using the specified Content Security Policy.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The delegate used to configure the Content Security Policy options.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddNWebsec(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] Action<IFluentCspOptions> configuration) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            return builder.AddModule("NWebsec", 5, app => {
                // Insert a new middleware responsible of setting the Content-Security-Policy header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
                app.UseCsp(configuration);

                // Insert a new middleware responsible of setting the X-Content-Type-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                app.UseXContentTypeOptions();

                // Insert a new middleware responsible of setting the X-Frame-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                app.UseXfo(xfo => xfo.Deny());

                // Insert a new middleware responsible of setting the X-Xss-Protection header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                app.UseXXssProtection(xss => xss.EnabledWithBlockMode());
            });
        }

        /// <summary>
        /// Registers the CORS module.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <param name="configuration">The delegate used to configure the CORS policy.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddCors(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] Action<CorsPolicyBuilder> configuration) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            builder.Services.AddCors();
            builder.AddModule("CORS", -10, map => map.UseCors(configuration));

            return builder;
        }
    }
}
