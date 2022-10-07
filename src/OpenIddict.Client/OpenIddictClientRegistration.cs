/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

/// <summary>
/// Contains the properties used to configure a client/server link.
/// </summary>
[DebuggerDisplay("{Issuer,nq}")]
public class OpenIddictClientRegistration
{
    /// <summary>
    /// Gets or sets the client identifier assigned by the authorization server.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret assigned by the authorization server, if applicable.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the address of the redirection endpoint that will handle the callback.
    /// </summary>
    public Uri? RedirectUri { get; set; }

    /// <summary>
    /// Gets or sets the address of the post-logout redirection endpoint that will handle the callback.
    /// </summary>
    public Uri? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Gets the list of encryption credentials used to create tokens for this client.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// </summary>
    public List<EncryptingCredentials> EncryptionCredentials { get; } = new();

    /// <summary>
    /// Gets the list of signing credentials used to create tokens for this client.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// </summary>
    public List<SigningCredentials> SigningCredentials { get; } = new();

    /// <summary>
    /// Gets the code challenge methods allowed by the client instance.
    /// If no value is explicitly set, the default code challenge methods are automatically used.
    /// </summary>
    /// <remarks>
    /// The final code challenge method used in authorization requests is chosen by OpenIddict
    /// based on the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> CodeChallengeMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the grant types allowed by the client instance.
    /// If no value is explicitly set, the default grant types are automatically used.
    /// </summary>
    /// <remarks>
    /// The final grant type used in authorization requests is chosen by OpenIddict
    /// based on the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the response type combinations allowed by the client instance.
    /// If no value is explicitly set, the default response types are automatically used.
    /// </summary>
    /// <remarks>
    /// The final response type used in authorization requests is chosen by OpenIddict
    /// based on the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the response modes allowed by the client instance.
    /// If no value is explicitly set, the default response modes are automatically used.
    /// </summary>
    /// <remarks>
    /// The final response method used in authorization requests is chosen by OpenIddict
    /// based on the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ResponseModes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the address of the authorization server.
    /// </summary>
    public Uri? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the provider name, if applicable.
    /// </summary>
    /// <remarks>
    /// If a Web provider integration with the same name was enabled, the
    /// provider-specific options will be automatically imported and applied.
    /// </remarks>
    public string? ProviderName { get; set; }

    /// <summary>
    /// Gets or sets the static server configuration, if applicable.
    /// </summary>
    public OpenIddictConfiguration? Configuration { get; set; }

    /// <summary>
    /// Gets or sets the configuration manager used to retrieve and cache the server configuration.
    /// </summary>
    public IConfigurationManager<OpenIddictConfiguration> ConfigurationManager { get; set; } = default!;

    /// <summary>
    /// Gets or sets the address of the authorization endpoint exposed by the server.
    /// </summary>
    public Uri? AuthorizationEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the address of the token endpoint exposed by the server.
    /// </summary>
    public Uri? TokenEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the token validation parameters associated with the authorization server.
    /// </summary>
    public TokenValidationParameters TokenValidationParameters { get; } = new TokenValidationParameters
    {
        AuthenticationType = TokenValidationParameters.DefaultAuthenticationType,
        ClockSkew = TimeSpan.Zero,
        NameClaimType = Claims.Name,
        RoleClaimType = Claims.Role,
        // Note: audience and lifetime are manually validated by OpenIddict itself.
        ValidateAudience = false,
        ValidateLifetime = false
    };

    /// <summary>
    /// Gets or sets the URL of the OAuth 2.0/OpenID Connect server discovery endpoint.
    /// When the URL is relative, <see cref="Issuer"/> must be set and absolute.
    /// </summary>
    public Uri? MetadataAddress { get; set; }

    /// <summary>
    /// Gets the list of scopes sent by default as part of authorization requests.
    /// </summary>
    public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the bag used to store additional provider-specific properties.
    /// </summary>
    public Dictionary<string, object?> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);
}
