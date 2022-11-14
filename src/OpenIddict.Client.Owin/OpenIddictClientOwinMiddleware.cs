/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Extensions.Options;
using Microsoft.Owin.Security.Infrastructure;

namespace OpenIddict.Client.Owin;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict client handler in an OWIN pipeline.
/// Note: this middleware is intented to be used with dependency injection containers
/// that support middleware resolution, like Autofac. Since it depends on scoped services,
/// it is NOT recommended to instantiate it as a singleton like a regular OWIN middleware.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientOwinMiddleware : AuthenticationMiddleware<OpenIddictClientOwinOptions>
{
    private readonly IOpenIddictClientDispatcher _dispatcher;
    private readonly IOpenIddictClientFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientOwinMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    /// <param name="options">The OpenIddict client OWIN options.</param>
    /// <param name="dispatcher">The OpenIddict client dispatcher.</param>
    /// <param name="factory">The OpenIddict client factory.</param>
    public OpenIddictClientOwinMiddleware(
        OwinMiddleware? next,
        IOptionsMonitor<OpenIddictClientOwinOptions> options,
        IOpenIddictClientDispatcher dispatcher,
        IOpenIddictClientFactory factory)
        : base(next, options.CurrentValue)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <summary>
    /// Creates and returns a new <see cref="OpenIddictClientOwinHandler"/> instance.
    /// </summary>
    /// <returns>A new instance of the <see cref="OpenIddictClientOwinHandler"/> class.</returns>
    protected override AuthenticationHandler<OpenIddictClientOwinOptions> CreateHandler()
        => new OpenIddictClientOwinHandler(_dispatcher, _factory);
}
