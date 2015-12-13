// Copyright (c) André N. Klingsheim. See License.txt in the project root for license information.

using System;
using NWebsec.Core.HttpHeaders.Configuration.Validation;
using NWebsec.Middleware;
using NWebsec.Middleware.Middleware;

// ReSharper disable once CheckNamespace
namespace Microsoft.AspNet.Builder
{
    public static class ApplicationBuilderExtensions
    {
        /// <summary>
        ///     Adds a middleware to the pipeline that validates redirects.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseRedirectValidation(this IApplicationBuilder app)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            var options = new RedirectValidationOptions();
            return app.UseMiddleware<RedirectValidationMiddleware>(options);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that validates redirects.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseRedirectValidation(this IApplicationBuilder app, Action<IFluentRedirectValidationOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new RedirectValidationOptions();
            configurer(options);
            return app.UseMiddleware<RedirectValidationMiddleware>(options);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the Strict-Transport-Security header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseHsts(this IApplicationBuilder app, Action<IFluentHstsOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new HstsOptions();
            configurer(options);
            new HstsConfigurationValidator().Validate(options);
            return app.UseMiddleware<HstsMiddleware>(options);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the Public-Key-Pins header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseHpkp(this IApplicationBuilder app, Action<IFluentHpkpOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new HpkpOptions();
            configurer(options);
            new HpkpConfigurationValidator().ValidateNumberOfPins(options.Config);
            return app.UseMiddleware<HpkpMiddleware>(options, false);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the Public-Key-Pins-Report-Only header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseHpkpReportOnly(this IApplicationBuilder app, Action<IFluentHpkpOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new HpkpOptions();
            configurer(options);
            new HpkpConfigurationValidator().ValidateNumberOfPins(options.Config);
            return app.UseMiddleware<HpkpMiddleware>(options, true);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the X-Content-Type-Options header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseXContentTypeOptions(this IApplicationBuilder app)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            return app.UseMiddleware<XContentTypeOptionsMiddleware>();
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the X-Download-Options header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseXDownloadOptions(this IApplicationBuilder app)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));

            return app.UseMiddleware<XDownloadOptionsMiddleware>();
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the X-Frame-Options header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseXfo(this IApplicationBuilder app, Action<IFluentXFrameOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new XFrameOptions();
            configurer(options);
            return app.UseMiddleware<XfoMiddleware>(options);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the X-Robots-Tag header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseXRobotsTag(this IApplicationBuilder app, Action<IFluentXRobotsTagOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new XRobotsTagOptions();
            configurer(options);
            return app.UseMiddleware<XRobotsTagMiddleware>(options);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the X-Xss-Protection header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseXXssProtection(this IApplicationBuilder app, Action<IFluentXXssProtectionOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new XXssProtectionOptions();
            configurer(options);
            return app.UseMiddleware<XXssMiddleware>(options);
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the Content-Security-Policy header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseCsp(this IApplicationBuilder app, Action<IFluentCspOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new CspOptions();
            configurer(options);
            return app.UseMiddleware<CspMiddleware>(options, false); //Last param indicates it's not reportOnly.
        }

        /// <summary>
        ///     Adds a middleware to the ASP.NET pipeline that sets the Content-Security-Policy-Report-Only header.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder" /> to which the middleware is added.</param>
        /// <param name="configurer">An <see cref="Action" /> that configures the options for the middleware.</param>
        /// <returns>The <see cref="IApplicationBuilder" /> supplied in the app parameter.</returns>
        public static IApplicationBuilder UseCspReportOnly(this IApplicationBuilder app, Action<IFluentCspOptions> configurer)
        {
            if (app == null) throw new ArgumentNullException(nameof(app));
            if (configurer == null) throw new ArgumentNullException(nameof(configurer));

            var options = new CspOptions();
            configurer(options);
            return app.UseMiddleware<CspMiddleware>(options, true); //Last param indicates it's reportOnly.
        }
    }
}