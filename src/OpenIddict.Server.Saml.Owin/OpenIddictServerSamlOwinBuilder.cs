/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Server.Saml.Owin;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict SAML OWIN/Katana integration.
/// </summary>
public sealed class OpenIddictServerSamlOwinBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictServerSamlOwinBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictServerSamlOwinBuilder(IServiceCollection services)
        => Services = services ?? throw new ArgumentNullException(nameof(services));

    /// <summary>
    /// Gets the services collection.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public IServiceCollection Services { get; }

    /// <summary>
    /// Amends the default OpenIddict SAML OWIN/Katana configuration.
    /// </summary>
    /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <returns>The <see cref="OpenIddictServerSamlOwinBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictServerSamlOwinBuilder Configure(Action<OpenIddictServerSamlOwinOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Sets the path of the metadata endpoint.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictServerSamlOwinBuilder"/> instance.</returns>
    public OpenIddictServerSamlOwinBuilder SetMetadataPath(PathString path)
        => Configure(options => options.MetadataPath = path);

    /// <summary>
    /// Sets the path of the single sign-on endpoint.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictServerSamlOwinBuilder"/> instance.</returns>
    public OpenIddictServerSamlOwinBuilder SetSingleSignOnPath(PathString path)
        => Configure(options => options.SingleSignOnPath = path);

    /// <summary>
    /// Sets the authentication type used to authenticate and challenge the user.
    /// </summary>
    /// <param name="type">The authentication type.</param>
    /// <returns>The <see cref="OpenIddictServerSamlOwinBuilder"/> instance.</returns>
    public OpenIddictServerSamlOwinBuilder SetAuthenticationType(string type)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);

        return Configure(options => options.AuthenticationType = type);
    }

    /// <summary>
    /// Sets the lifetime of the protected request state attached to the return URL.
    /// </summary>
    /// <param name="lifetime">The lifetime.</param>
    /// <returns>The <see cref="OpenIddictServerSamlOwinBuilder"/> instance.</returns>
    public OpenIddictServerSamlOwinBuilder SetRequestStateLifetime(TimeSpan lifetime)
        => Configure(options => options.RequestStateLifetime = lifetime);

    /// <summary>
    /// Allows the SAML endpoints to be used over HTTP (not recommended outside development environments).
    /// </summary>
    /// <returns>The <see cref="OpenIddictServerSamlOwinBuilder"/> instance.</returns>
    public OpenIddictServerSamlOwinBuilder DisableTransportSecurityRequirement()
        => Configure(options => options.DisableTransportSecurityRequirement = true);
}
