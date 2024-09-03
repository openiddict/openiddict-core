/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.AspNetCore;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure
/// the OpenIddict client ASP.NET Core integration.
/// </summary>
public sealed class OpenIddictClientAspNetCoreBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientAspNetCoreBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientAspNetCoreBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict client ASP.NET Core configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBuilder Configure(Action<OpenIddictClientAspNetCoreOptions> configuration)
    {
        if (configuration is null)
        {
            throw new ArgumentNullException(nameof(configuration));
        }

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Disables automatic authentication scheme forwarding. When automatic forwarding
    /// is disabled, static client registrations are not mapped as individual
    /// authentication schemes and calls to <see cref="IAuthenticationService"/> such as
    /// <see cref="IAuthenticationService.ChallengeAsync(HttpContext, string, AuthenticationProperties)"/>
    /// cannot directly use the provider name associated to a client registration as the authentication
    /// scheme and must set the provider name (or the issuer) as an authentication property instead.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBuilder DisableAutomaticAuthenticationSchemeForwarding()
        => Configure(options => options.DisableAutomaticAuthenticationSchemeForwarding = true);

    /// <summary>
    /// Adds the specified authentication scheme to the list of forwarded authentication
    /// schemes that are managed by the OpenIddict ASP.NET Core client host.
    /// </summary>
    /// <remarks>
    /// Note: the <paramref name="provider"/> parameter MUST match
    /// an existing <see cref="OpenIddictClientRegistration.ProviderName"/>.
    /// </remarks>
    /// <param name="provider">The provider name, also used as the authentication scheme.</param>
    /// <param name="caption">The caption that will be used as the public/user-visible display name, if applicable.</param>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientAspNetCoreBuilder AddForwardedAuthenticationScheme(string provider, string? caption)
    {
        if (string.IsNullOrEmpty(provider))
        {
            throw new ArgumentException(SR.FormatID0366(nameof(provider)), nameof(provider));
        }

        return Configure(options => options.ForwardedAuthenticationSchemes.Add(
            new AuthenticationScheme(provider, caption, typeof(OpenIddictClientAspNetCoreForwarder))));
    }

    /// <summary>
    /// Disables the transport security requirement (HTTPS).
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBuilder DisableTransportSecurityRequirement()
        => Configure(options => options.DisableTransportSecurityRequirement = true);

    /// <summary>
    /// Enables the pass-through mode for the OpenID Connect post-logout redirection endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBuilder EnablePostLogoutRedirectionEndpointPassthrough()
        => Configure(options => options.EnablePostLogoutRedirectionEndpointPassthrough = true);

    /// <summary>
    /// Enables the pass-through mode for the OpenID Connect redirection endpoint.
    /// When the pass-through mode is used, OpenID Connect requests are initially handled by OpenIddict.
    /// Once validated, the rest of the request processing pipeline is invoked, so that OpenID Connect requests
    /// can be handled at a later stage (in a custom middleware or in a MVC controller, for instance).
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBuilder EnableRedirectionEndpointPassthrough()
        => Configure(options => options.EnableRedirectionEndpointPassthrough = true);

    /// <summary>
    /// Enables error pass-through support, so that the rest of the request processing pipeline is
    /// automatically invoked when returning an error from the interactive authorization and end session endpoints.
    /// When this option is enabled, special logic must be added to these actions to handle errors, that can be
    /// retrieved using <see cref="OpenIddictClientAspNetCoreHelpers.GetOpenIddictClientResponse(HttpContext)"/>.
    /// </summary>
    /// <remarks>
    /// Important: the error pass-through mode cannot be used when the status code pages integration is enabled.
    /// </remarks>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientAspNetCoreBuilder EnableErrorPassthrough()
        => Configure(options => options.EnableErrorPassthrough = true);

    /// <summary>
    /// Enables status code pages integration support. Once enabled, errors
    /// generated by the interactive endpoints can be handled by ASP.NET Core.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictClientAspNetCoreBuilder EnableStatusCodePagesIntegration()
        => Configure(options => options.EnableStatusCodePagesIntegration = true);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => base.Equals(obj);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override string? ToString() => base.ToString();
}
