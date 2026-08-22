/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.Owin.Security.Infrastructure;

namespace OpenIddict.Server.Owin;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict server handler in an OWIN pipeline.
/// </summary>
/// <remarks>
/// Note: this middleware is intended to be used with dependency injection containers
/// that support middleware resolution, like Autofac. Since it depends on scoped services,
/// it is NOT recommended to instantiate it as a singleton like a regular OWIN middleware.
/// </remarks>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerOwinMiddleware : AuthenticationMiddleware<AuthenticationOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerOwinMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    /// <param name="provider">The service provider.</param>
    public OpenIddictServerOwinMiddleware(
        OwinMiddleware? next,
        IServiceProvider provider)
        : base(next, new InternalOptions())
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <summary>
    /// Creates and returns a new <see cref="OpenIddictServerOwinHandler"/> instance.
    /// </summary>
    /// <returns>A new instance of the <see cref="OpenIddictServerOwinHandler"/> class.</returns>
    protected override AuthenticationHandler<AuthenticationOptions> CreateHandler()
        => new OpenIddictServerOwinHandler(_provider);

    /// <summary>
    /// Provides the options used by the <see cref="OpenIddictServerOwinMiddleware"/> class.
    /// </summary>
    private sealed class InternalOptions : AuthenticationOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="InternalOptions"/> class.
        /// </summary>
        public InternalOptions() : base(OpenIddictServerOwinDefaults.AuthenticationType)
            => AuthenticationMode = AuthenticationMode.Passive;
    }
}
