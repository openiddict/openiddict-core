/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNet.Identity;
using Microsoft.Extensions.Internal;
using OpenIddict.Models;

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static IdentityBuilder AddOpenIddict([NotNull] this IdentityBuilder builder) {
            return builder.AddOpenIddictCore<Application>(configuration => {
                // Use the EF adapter by default.
                configuration.UseEntityFramework();
            });
        }

        public static IdentityBuilder AddOpenIddict<TApplication>([NotNull] this IdentityBuilder builder)
            where TApplication : Application {
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
            return app.UseOpenIddictCore(builder => {
                builder.UseAssets();
                builder.UseCors();
                builder.UseNWebsec();
                builder.UseMvc();

                configuration(builder);
            });
        }
    }
}