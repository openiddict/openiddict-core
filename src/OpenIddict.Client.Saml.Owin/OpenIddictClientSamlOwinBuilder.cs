/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using OpenIddict.Client.Saml.Owin;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes the necessary methods required to configure the OpenIddict SAML service provider OWIN/Katana integration.
/// </summary>
public sealed class OpenIddictClientSamlOwinBuilder
{
    /// <summary>
    /// Initializes a new instance of <see cref="OpenIddictClientSamlOwinBuilder"/>.
    /// </summary>
    /// <param name="services">The services collection.</param>
    public OpenIddictClientSamlOwinBuilder(IServiceCollection services)
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
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public OpenIddictClientSamlOwinBuilder Configure(Action<OpenIddictClientSamlOwinOptions> configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        Services.Configure(configuration);

        return this;
    }

    /// <summary>
    /// Sets the path of the assertion consumer service.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    public OpenIddictClientSamlOwinBuilder SetAssertionConsumerServicePath(PathString path)
        => Configure(options => options.AssertionConsumerServicePath = path);

    /// <summary>
    /// Sets the path of the service provider metadata endpoint.
    /// </summary>
    /// <param name="path">The path.</param>
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    public OpenIddictClientSamlOwinBuilder SetMetadataPath(PathString path)
        => Configure(options => options.MetadataPath = path);

    /// <summary>
    /// Sets the authentication type used to sign the user in once the assertion is validated.
    /// </summary>
    /// <param name="type">The authentication type.</param>
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    public OpenIddictClientSamlOwinBuilder SetSignInAuthenticationType(string type)
    {
        ArgumentException.ThrowIfNullOrEmpty(type);

        return Configure(options => options.SignInAuthenticationType = type);
    }

    /// <summary>
    /// Enables the pass-through mode for the assertion consumer service: validated requests are
    /// handed to the application, that is responsible for signing the user in.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    public OpenIddictClientSamlOwinBuilder EnableAssertionConsumerServicePassthrough()
        => Configure(options => options.EnableAssertionConsumerServicePassthrough = true);

    /// <summary>
    /// Disables the automatic handling of the SAML registration provider names as challenge authentication types.
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    public OpenIddictClientSamlOwinBuilder DisableAutomaticAuthenticationTypeForwarding()
        => Configure(options => options.DisableAutomaticAuthenticationTypeForwarding = true);

    /// <summary>
    /// Allows the SAML endpoints to be used over HTTP (not recommended outside development environments).
    /// </summary>
    /// <returns>The <see cref="OpenIddictClientSamlOwinBuilder"/> instance.</returns>
    public OpenIddictClientSamlOwinBuilder DisableTransportSecurityRequirement()
        => Configure(options => options.DisableTransportSecurityRequirement = true);
}
