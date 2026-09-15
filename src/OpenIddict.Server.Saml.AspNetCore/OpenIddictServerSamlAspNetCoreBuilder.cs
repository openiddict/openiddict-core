/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Server.Saml.AspNetCore;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict SAML ASP.NET Core integration.
/// </summary>
public sealed class OpenIddictServerSamlAspNetCoreBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerSamlAspNetCoreBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerSamlAspNetCoreBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict SAML ASP.NET Core configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSamlAspNetCoreBuilder Configure(Action<OpenIddictServerSamlAspNetCoreOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Sets the path of the metadata endpoint.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerSamlAspNetCoreBuilder SetMetadataPath(PathString path)
        => Configure(options => options.MetadataPath = path);

    /// <summary>
    /// Sets the path of the single sign-on endpoint.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerSamlAspNetCoreBuilder SetSingleSignOnPath(PathString path)
        => Configure(options => options.SingleSignOnPath = path);

    /// <summary>
    /// Sets the path of the artifact resolution endpoint.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerSamlAspNetCoreBuilder SetArtifactResolutionPath(PathString path)
        => Configure(options => options.ArtifactResolutionPath = path);

    /// <summary>
    /// Sets the path of the single logout endpoint.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerSamlAspNetCoreBuilder SetSingleLogoutPath(PathString path)
        => Configure(options => options.SingleLogoutPath = path);

    /// <summary>
    /// Sets the authentication scheme used to authenticate and challenge the user.
    /// </summary>
    /// <param name="scheme">The authentication scheme.</param>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerSamlAspNetCoreBuilder SetAuthenticationScheme(string scheme)
    {
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        return Configure(options => options.AuthenticationScheme = scheme);
    }

    /// <summary>
    /// Sets the lifetime of the protected request state attached to the return URL.
    /// </summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerSamlAspNetCoreBuilder SetRequestStateLifetime(TimeSpan lifetime)
        => Configure(options => options.RequestStateLifetime = lifetime);

    /// <summary>
    /// Allows the SAML endpoints to be used over HTTP (not recommended outside development environments).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlAspNetCoreBuilder"/> instance.</returns>
    public OpenIddictServerSamlAspNetCoreBuilder DisableTransportSecurityRequirement()
        => Configure(options => options.DisableTransportSecurityRequirement = true);
}
