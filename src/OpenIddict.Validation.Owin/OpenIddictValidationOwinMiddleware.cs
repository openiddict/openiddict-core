/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.Owin.Security.Infrastructure;

namespace OpenIddict.Validation.Owin;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict validation handler in an OWIN pipeline.
/// Note: this middleware is intented to be used with dependency injection containers
/// that support middleware resolution, like Autofac. Since it depends on scoped services,
/// it is NOT recommended to instantiate it as a singleton like a regular OWIN middleware.
/// </summary>
public class OpenIddictValidationOwinMiddleware : AuthenticationMiddleware<OpenIddictValidationOwinOptions>
{
    private readonly IOpenIddictValidationDispatcher _dispatcher;
    private readonly IOpenIddictValidationFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationOwinMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    /// <param name="options">The OpenIddict validation OWIN options.</param>
    /// <param name="dispatcher">The OpenIddict validation dispatcher.</param>
    /// <param name="factory">The OpenIddict validation factory.</param>
    public OpenIddictValidationOwinMiddleware(
        OwinMiddleware? next,
        IOptionsMonitor<OpenIddictValidationOwinOptions> options,
        IOpenIddictValidationDispatcher dispatcher,
        IOpenIddictValidationFactory factory)
        : base(next, options.CurrentValue)
    {
        _dispatcher = dispatcher;
        _factory = factory;
    }

    /// <summary>
    /// Creates and returns a new <see cref="OpenIddictValidationOwinHandler"/> instance.
    /// </summary>
    /// <returns>A new instance of the <see cref="OpenIddictValidationOwinHandler"/> class.</returns>
    protected override AuthenticationHandler<OpenIddictValidationOwinOptions> CreateHandler()
        => new OpenIddictValidationOwinHandler(_dispatcher, _factory);
}
