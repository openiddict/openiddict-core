/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.Options;
using Microsoft.Owin.Security.Infrastructure;

namespace OpenIddict.Server.Owin;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict server handler in an OWIN pipeline.
/// Note: this middleware is intented to be used with dependency injection containers
/// that support middleware resolution, like Autofac. Since it depends on scoped services,
/// it is NOT recommended to instantiate it as a singleton like a regular OWIN middleware.
/// </summary>
public sealed class OpenIddictServerOwinMiddleware : AuthenticationMiddleware<OpenIddictServerOwinOptions>
{
    private readonly IOpenIddictServerDispatcher _dispatcher;
    private readonly IOpenIddictServerFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerOwinMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    /// <param name="options">The OpenIddict server OWIN options.</param>
    /// <param name="dispatcher">The OpenIddict server dispatcher.</param>
    /// <param name="factory">The OpenIddict server factory.</param>
    public OpenIddictServerOwinMiddleware(
        OwinMiddleware? next,
        IOptionsMonitor<OpenIddictServerOwinOptions> options,
        IOpenIddictServerDispatcher dispatcher,
        IOpenIddictServerFactory factory)
        : base(next, options.CurrentValue)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <summary>
    /// Creates and returns a new <see cref="OpenIddictServerOwinHandler"/> instance.
    /// </summary>
    /// <returns>A new instance of the <see cref="OpenIddictServerOwinHandler"/> class.</returns>
    protected override AuthenticationHandler<OpenIddictServerOwinOptions> CreateHandler()
        => new OpenIddictServerOwinHandler(_dispatcher, _factory);
}
