/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Validation.Owin;

/// <summary>
/// Provides the entry point necessary to instantiate and register the scoped
/// <see cref="OpenIddictValidationOwinMiddleware"/> in an OWIN/Katana pipeline.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictValidationOwinMiddlewareFactory : OwinMiddleware
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationOwinMiddlewareFactory"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    public OpenIddictValidationOwinMiddlewareFactory(OwinMiddleware? next)
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
    public override Task Invoke(IOwinContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        var provider = context.Get<IServiceProvider>(typeof(IServiceProvider).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0168));

        // Note: the Microsoft.Extensions.DependencyInjection container doesn't support resolving services
        // with arbitrary parameters, which prevents the validation OWIN middleware from being resolved directly
        // from the DI container, as the next middleware in the pipeline cannot be specified as a parameter.
        // To work around this limitation, the validation OWIN middleware is manually instantiated and invoked.
        var middleware = new OpenIddictValidationOwinMiddleware(
            next: Next,
            options: GetRequiredService<IOptionsMonitor<OpenIddictValidationOwinOptions>>(provider),
            dispatcher: GetRequiredService<IOpenIddictValidationDispatcher>(provider),
            factory: GetRequiredService<IOpenIddictValidationFactory>(provider));

        return middleware.Invoke(context);

        static T GetRequiredService<T>(IServiceProvider provider) => provider.GetService<T>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0169));
    }
}
