/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Models;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        public static IdentityBuilder AddOpenIddict([NotNull] this IdentityBuilder builder) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddOpenIddictCore<Application>(configuration => {
                // Use the EF adapter by default.
                configuration.UseEntityFramework();
            });
        }

        public static IdentityBuilder AddOpenIddict<TApplication>([NotNull] this IdentityBuilder builder)
            where TApplication : class {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            return builder.AddOpenIddictCore<TApplication>(configuration => {
                // Use the EF adapter by default.
                configuration.UseEntityFramework();
            });
        }

        public static IApplicationBuilder UseOpenIddict([NotNull] this IApplicationBuilder app) {
            return app.UseOpenIddict(options => { });
        }

        public static IApplicationBuilder UseOpenIddict(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIddictBuilder> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            return app.UseOpenIddictCore(builder => {
                builder.UseAssets();
                builder.UseNWebsec();
                builder.UseMvc();

                configuration(builder);
            });
        }
    }
}