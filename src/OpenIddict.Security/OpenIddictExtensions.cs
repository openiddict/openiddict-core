using System;
using Microsoft.Extensions.Internal;
using NWebsec.Middleware;

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictBuilder UseNWebsec([NotNull] this OpenIddictBuilder builder) {
            return builder.UseNWebsec(options => {
                options.DefaultSources(directive => directive.Self())
                       .ImageSources(directive => directive.Self().CustomSources("*"))
                       .ScriptSources(directive => directive.Self().UnsafeInline())
                       .StyleSources(directive => directive.Self().UnsafeInline());
            });
        }

        public static OpenIddictBuilder UseNWebsec(
            [NotNull] this OpenIddictBuilder builder,
            [NotNull] Action<IFluentCspOptions> configuration) {
            return builder.AddModule("NWebsec", 5, app => {
                // Insert a new middleware responsible of setting the Content-Security-Policy header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
                app.UseCsp(configuration);

                // Insert a new middleware responsible of setting the X-Content-Type-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                app.UseXContentTypeOptions();

                // Insert a new middleware responsible of setting the X-Frame-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                app.UseXfo(options => options.Deny());

                // Insert a new middleware responsible of setting the X-Xss-Protection header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                app.UseXXssProtection(options => options.EnabledWithBlockMode());
            });
        }

        public static OpenIddictBuilder UseCors([NotNull] this OpenIddictBuilder builder) {
            //Add CORS to the app
            builder.AddModule("CORS", -10, map => map.UseCors(options => {
                options.AllowAnyHeader();
                options.AllowAnyMethod();
                options.AllowAnyOrigin();
                options.AllowCredentials();
            }));

            return builder;
        }
    }
}
