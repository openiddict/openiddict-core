/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Owin;

namespace OpenIddict.Validation.Owin
{
    /// <summary>
    /// Provides the entry point necessary to instantiate and register the scoped
    /// <see cref="OpenIddictValidationOwinMiddleware"/> in an OWIN/Katana pipeline.
    /// </summary>
    public class OpenIddictValidationOwinMiddlewareFactory : OwinMiddleware
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictValidationOwinMiddlewareFactory"/> class.
        /// </summary>
        /// <param name="next">The next middleware in the pipeline, if applicable.</param>
        public OpenIddictValidationOwinMiddlewareFactory([CanBeNull] OwinMiddleware next)
            : base(next)
        {
        }

        /// <summary>
        /// Resolves the <see cref="IServiceProvider"/> instance from the OWIN context
        /// and creates a new instance of the <see cref="OpenIddictValidationOwinMiddleware"/> class,
        /// which is used to register <see cref="OpenIddictValidationOwinHandler"/> in the pipeline.
        /// </summary>
        /// <param name="context">The <see cref="IOwinContext"/>.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        public override Task Invoke([NotNull] IOwinContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var provider = context.Get<IServiceProvider>(typeof(IServiceProvider).FullName);
            if (provider == null)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .Append("No service provider was found in the OWIN context. For the OpenIddict validation ")
                    .Append("services to work correctly, a per-request 'IServiceProvider' must be attached ")
                    .AppendLine("to the OWIN environment with the dictionary key 'System.IServiceProvider'.")
                    .Append("Note: when using a dependency injection container supporting middleware resolution ")
                    .Append("(like Autofac), the 'app.UseOpenIddictValidation()' extension MUST NOT be called.")
                    .ToString());
            }

            // Note: the Microsoft.Extensions.DependencyInjection container doesn't support resolving services
            // with arbitrary parameters, which prevents the validation OWIN middleware from being resolved directly
            // from the DI container, as the next middleware in the pipeline cannot be specified as a parameter.
            // To work around this limitation, the validation OWIN middleware is manually instantiated and invoked.
            var middleware = new OpenIddictValidationOwinMiddleware(
                next: Next,
                options: GetRequiredService<IOptionsMonitor<OpenIddictValidationOwinOptions>>(provider),
                provider: GetRequiredService<IOpenIddictValidationProvider>(provider));

            return middleware.Invoke(context);

            static T GetRequiredService<T>(IServiceProvider provider)
                => provider.GetService<T>() ?? throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("The OpenIddict validation authentication services cannot be resolved from the DI container.")
                    .Append("To register the OWIN services, use 'services.AddOpenIddict().AddValidation().UseOwin()'.")
                    .ToString());
        }
    }
}
