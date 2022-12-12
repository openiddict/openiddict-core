/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

/// <summary>
/// Provides various settings needed to configure the OpenIddict client handler.
/// </summary>
public sealed class OpenIddictClientOptions
{
    /// <summary>
    /// Gets or sets the optional URI used to uniquely identify the client/relying party.
    /// The URI must be absolute and may contain a path, but no query string or fragment part.
    /// </summary>
    public Uri? ClientUri { get; set; }

    /// <summary>
    /// Gets the list of the handlers responsible for processing the OpenIddict client operations.
    /// Note: the list is automatically sorted based on the order assigned to each handler descriptor.
    /// As such, it MUST NOT be mutated after options initialization to preserve the exact order.
    /// </summary>
    public List<OpenIddictClientHandlerDescriptor> Handlers { get; } = new(DefaultHandlers);

    /// <summary>
    /// Gets the list of encryption credentials used by the OpenIddict client services.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// Note: the encryption credentials are not used to protect/unprotect tokens issued
    /// by ASP.NET Core Data Protection, that uses its own key ring, configured separately.
    /// </summary>
    /// <remarks>
    /// Note: OpenIddict automatically sorts the credentials based on the following algorithm:
    /// <list type="bullet">
    ///   <item><description>Symmetric keys are always preferred when they can be used for the operation (e.g token encryption).</description></item>
    ///   <item><description>X.509 keys are always preferred to non-X.509 asymmetric keys.</description></item>
    ///   <item><description>X.509 keys with the furthest expiration date are preferred.</description></item>
    ///   <item><description>X.509 keys whose backing certificate is not yet valid are never preferred.</description></item>
    /// </list>
    /// </remarks>
    public List<EncryptingCredentials> EncryptionCredentials { get; } = new();

    /// <summary>
    /// Gets the list of signing credentials used by the OpenIddict client services.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// Note: the signing credentials are not used to protect/unprotect tokens issued
    /// by ASP.NET Core Data Protection, that uses its own key ring, configured separately.
    /// </summary>
    /// <remarks>
    /// Note: OpenIddict automatically sorts the credentials based on the following algorithm:
    /// <list type="bullet">
    ///   <item><description>Symmetric keys are always preferred when they can be used for the operation (e.g token signing).</description></item>
    ///   <item><description>X.509 keys are always preferred to non-X.509 asymmetric keys.</description></item>
    ///   <item><description>X.509 keys with the furthest expiration date are preferred.</description></item>
    ///   <item><description>X.509 keys whose backing certificate is not yet valid are never preferred.</description></item>
    /// </list>
    /// </remarks>
    public List<SigningCredentials> SigningCredentials { get; } = new();

    /// <summary>
    /// Gets or sets the period of time client assertion tokens remain valid after being issued. The default value is 5 minutes.
    /// While not recommended, this property can be set to <see langword="null"/> to issue client assertion tokens that never expire.
    /// </summary>
    public TimeSpan? ClientAssertionTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the period of time state tokens remain valid after being issued. The default value is 15 minutes.
    /// While not recommended, this property can be set to <see langword="null"/> to issue state tokens that never expire.
    /// </summary>
    public TimeSpan? StateTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Gets or sets the security token handler used to protect and unprotect tokens.
    /// </summary>
    public JsonWebTokenHandler JsonWebTokenHandler { get; set; } = new JsonWebTokenHandler
    {
        SetDefaultTimesOnTokenCreation = false
    };

    /// <summary>
    /// Gets the absolute and relative URIs associated to the redirection endpoint.
    /// </summary>
    public List<Uri> RedirectionEndpointUris { get; } = new();

    /// <summary>
    /// Gets the absolute and relative URIs associated to the post-logout redirection endpoint.
    /// </summary>
    public List<Uri> PostLogoutRedirectionEndpointUris { get; } = new();

    /// <summary>
    /// Gets the static client registrations used by the OpenIddict client services.
    /// </summary>
    public List<OpenIddictClientRegistration> Registrations { get; } = new();

    /// <summary>
    /// Gets the token validation parameters used by the OpenIddict client services.
    /// </summary>
    /// <remarks>
    /// This instance is not used to validate tokens issued by remote authorization servers
    /// and is only used with tokens produced and validated by the client itself (e.g state tokens).
    /// </remarks>
    public TokenValidationParameters TokenValidationParameters { get; } = new()
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
    /// Gets or sets a boolean indicating whether token storage should be disabled.
    /// When disabled, no database entry is created for the tokens created by the
    /// OpenIddict client services. Using this option is generally NOT recommended.
    /// </summary>
    public bool DisableTokenStorage { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0 code challenge methods enabled for this application.
    /// By default, only the S256 method is allowed (if the code flow is enabled).
    /// </summary>
    public HashSet<string> CodeChallengeMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect flows enabled for this application.
    /// </summary>
    public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect response types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect response modes enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> ResponseModes { get; } = new(StringComparer.Ordinal);
}
