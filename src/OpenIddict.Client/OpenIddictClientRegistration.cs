/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

/// <summary>
/// Contains the properties used to configure a client/server link.
/// </summary>
[DebuggerDisplay("{Issuer,nq}")]
public sealed class OpenIddictClientRegistration
{
    /// <summary>
    /// Gets or sets the unique identifier assigned to the registration.
    /// </summary>
    public string? RegistrationId { get; set; }

    /// <summary>
    /// Gets or sets the client identifier assigned by the authorization server.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret assigned by the authorization server, if applicable.
    /// </summary>
    /// <remarks>
    /// Note: client authentication based on shared secrets is not recommended and should
    /// only be used for backward compatibility with legacy applications that only support
    /// client secrets. When possible, consider using public/private key pairs or TLS client
    /// certificates instead, as these client authentication methods are significantly safer.
    /// </remarks>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether pushed authorization requests are disabled.
    /// When pushed authorization requests are disabled, PAR is not used by the OpenIddict client,
    /// even if the remote authorization server exposes a pushed authorization endpoint. If the
    /// authorization server requires using PAR but this property is set to <see langword="null"/>,
    /// an exception is automatically thrown when starting an interactive authentication challenge.
    /// </summary>
    public bool DisablePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether authorization requests should be sent as signed request objects
    /// (JWT-secured authorization requests, RFC 9101). Request objects are always sent when the authorization server
    /// requires them. When enabled, request objects are signed using the first asymmetric signing key attached to
    /// the client registration and are sent only if the authorization server supports the "request" parameter.
    /// </summary>
    public bool UseSignedRequestObjects { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether backchannel authentication requests (CIBA) should be sent as signed
    /// authentication requests using the "request" parameter. When enabled, the authentication request parameters are
    /// sent as a JWT signed using the first asymmetric signing key attached to the client registration, whose algorithm
    /// must be listed in the "backchannel_authentication_request_signing_alg_values_supported" server metadata.
    /// </summary>
    public bool UseSignedBackchannelAuthenticationRequests { get; set; }

    /// <summary>
    /// Gets or sets the URI of the redirection endpoint that will handle the callback.
    /// </summary>
    /// <remarks>
    /// Note: this value is automatically added to
    /// <see cref="OpenIddictClientOptions.RedirectionEndpointUris"/>.
    /// </remarks>
    public Uri? RedirectUri { get; set; }

    /// <summary>
    /// Gets or sets the URI of the post-logout redirection endpoint that will handle the callback.
    /// </summary>
    /// <remarks>
    /// Note: this value is automatically added to
    /// <see cref="OpenIddictClientOptions.PostLogoutRedirectionEndpointUris"/>.
    /// </remarks>
    public Uri? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Gets or sets the URI of the back-channel logout endpoint registered for this client at the authorization server
    /// ("backchannel_logout_uri" client metadata, OpenID Connect Back-Channel Logout 1.0, section 2.2).
    /// </summary>
    /// <remarks>
    /// Note: this value is automatically added to <see cref="OpenIddictClientOptions.BackchannelLogoutEndpointUris"/>
    /// for static registrations.
    /// </remarks>
    public Uri? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the logout tokens sent by the authorization server must include
    /// a "sid" claim ("backchannel_logout_session_required" client metadata, OpenID Connect Back-Channel Logout 1.0,
    /// section 2.2). When enabled, logout tokens that don't include a "sid" claim are rejected.
    /// </summary>
    public bool BackchannelLogoutSessionRequired { get; set; }

    /// <summary>
    /// Gets or sets the URI of the front-channel logout endpoint registered for this client at the authorization server
    /// ("frontchannel_logout_uri" client metadata, OpenID Connect Front-Channel Logout 1.0, section 2).
    /// </summary>
    /// <remarks>
    /// Note: this value is automatically added to <see cref="OpenIddictClientOptions.FrontchannelLogoutEndpointUris"/>
    /// for static registrations.
    /// </remarks>
    public Uri? FrontchannelLogoutUri { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the authorization server must send the "iss" and "sid" parameters to
    /// the front-channel logout endpoint ("frontchannel_logout_session_required" client metadata, OpenID Connect
    /// Front-Channel Logout 1.0, section 2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Important: the default value (<see langword="true"/>) deliberately differs from the default value defined by the
    /// specification (<see langword="false"/>) and MUST match the "frontchannel_logout_session_required" metadata registered
    /// for this client at the authorization server: if the authorization server doesn't send these parameters,
    /// all the front-channel logout requests are rejected (and a warning is logged).
    /// </para>
    /// <para>
    /// Security warning: when set to <see langword="false"/>, front-channel logout requests without parameters cannot
    /// be distinguished from requests forged by third-party websites: any page able to embed the front-channel logout
    /// endpoint in an iframe (which is required by the specification and typically implies using "SameSite=None" cookies)
    /// can sign the user out of this client registration (logout CSRF). Disabling this setting is not recommended.
    /// </para>
    /// Note: when set to <see langword="false"/>, front-channel logout requests that include neither "iss" nor "sid"
    /// are accepted if a unique registration not requiring these parameters can be resolved (using the front-channel
    /// logout URI when multiple registrations qualify): such requests only terminate the local session attached to the
    /// user agent (via the sign-out scheme/authentication type configured in the host) and don't invoke the session stores.
    /// Requests that include either parameter must always include both. Front-channel logout requests are not authenticated:
    /// session stores are only invoked for requests verified as being bound to the session of the user agent.
    /// </remarks>
    public bool FrontchannelLogoutSessionRequired { get; set; } = true;

    /// <summary>
    /// Gets the list of encryption credentials used to create tokens for this client.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// </summary>
    public List<EncryptingCredentials> EncryptionCredentials { get; } = [];

    /// <summary>
    /// Gets the list of signing credentials used to create tokens for this client.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// </summary>
    public List<SigningCredentials> SigningCredentials { get; } = [];

    /// <summary>
    /// Gets or sets the asymmetric signing credentials used to create DPoP proofs for this client.
    /// If DPoP token binding is enabled and no value is explicitly set, an ephemeral P-256 key is generated.
    /// </summary>
    /// <remarks>
    /// Note: when using an ephemeral key, DPoP-bound refresh tokens can't be used after the application restarts.
    /// </remarks>
    public SigningCredentials? DPoPSigningCredentials { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether introspection responses must be returned as JSON Web Tokens (RFC 9701).
    /// When enabled, introspection requests are sent with an "Accept: application/token-introspection+jwt" header
    /// and successful responses that are not signed by the authorization server are rejected.
    /// </summary>
    /// <remarks>
    /// Note: encrypted responses are decrypted using the encryption credentials registered in the client options.
    /// </remarks>
    public bool RequireJsonWebTokenIntrospectionResponses { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether authorization responses must be returned as JWTs using
    /// one of the JWT Secured Authorization Response Modes (JARM). When enabled, the negotiated response
    /// mode is replaced by its JWT variant ("query.jwt", "fragment.jwt" or "form_post.jwt") and
    /// authorization responses that are not returned as signed JWTs are rejected.
    /// </summary>
    /// <remarks>
    /// Note: encrypted responses are decrypted using the encryption credentials registered in the client options.
    /// </remarks>
    public bool RequireJwtSecuredAuthorizationResponses { get; set; }

    /// <summary>
    /// Gets the client authentication methods allowed by the client instance.
    /// If no value is explicitly set, all the methods enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final client authentication method used in backchannel requests is chosen by OpenIddict based
    /// on the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ClientAuthenticationMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the type of the client. If no value is explicitly set, the client is assumed to be
    /// "confidential" if a client secret or a signing key/certificate was assigned ("public" otherwise).
    /// </summary>
    public string? ClientType { get; set; }

    /// <summary>
    /// Gets the code challenge methods allowed by the client instance.
    /// If no value is explicitly set, all the methods enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final code challenge method used in authorization requests is chosen by OpenIddict based
    /// on the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> CodeChallengeMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the grant types allowed by the client instance.
    /// If no value is explicitly set, all the modes enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final grant type used in authorization requests is chosen by OpenIddict based on
    /// the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the response modes allowed by the client instance.
    /// If no value is explicitly set, all the modes enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final response method used in authorization requests is chosen by OpenIddict based on
    /// the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ResponseModes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the response type combinations allowed by the client instance.
    /// If no value is explicitly set, all the types enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final response type used in authorization requests is chosen by OpenIddict based on
    /// the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the token binding methods allowed by the client instance.
    /// If no value is explicitly set, all the methods enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final token binding method used in backchannel requests is chosen by OpenIddict based
    /// on the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> TokenBindingMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the issuer that will be attached to the <see cref="Claim"/>
    /// instances created by the OpenIddict client stack for this registration.
    /// </summary>
    /// <remarks>
    /// Note: if this property is not explicitly set, the provider name (if set)
    /// or the issuer URI are automatically used as a fallback value.
    /// </remarks>
    public string? ClaimsIssuer { get; set; }

    /// <summary>
    /// Gets or sets the URI of the authorization server.
    /// </summary>
    public Uri? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the provider display name.
    /// </summary>
    public string? ProviderDisplayName { get; set; }

    /// <summary>
    /// Gets or sets the provider name.
    /// </summary>
    /// <remarks>
    /// The provider name can be safely used as a stable public identifier.
    /// </remarks>
    public string? ProviderName { get; set; }

    /// <summary>
    /// Gets or sets the provider settings, if applicable.
    /// </summary>
    public dynamic? ProviderSettings { get; set; }

    /// <summary>
    /// Gets or sets the provider type, if applicable.
    /// </summary>
    /// <remarks>
    /// Note: when manually set, the specified value MUST match the type of an existing
    /// provider supported by the OpenIddict.Client.WebIntegration companion package.
    /// </remarks>
    public string? ProviderType { get; set; }

    /// <summary>
    /// Gets or sets the static server configuration, if applicable.
    /// </summary>
    public OpenIddictConfiguration? Configuration { get; set; }

    /// <summary>
    /// Gets or sets the configuration manager used to retrieve and cache the server configuration.
    /// </summary>
    public IConfigurationManager<OpenIddictConfiguration>? ConfigurationManager { get; set; }

    /// <summary>
    /// Gets or sets the URI of the configuration endpoint exposed by the server.
    /// When the URI is relative, <see cref="Issuer"/> must be set and absolute.
    /// </summary>
    public Uri? ConfigurationEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the token validation parameters associated with the authorization server.
    /// </summary>
    public TokenValidationParameters TokenValidationParameters { get; } = new TokenValidationParameters
    {
        AuthenticationType = TokenValidationParameters.DefaultAuthenticationType,
        ClockSkew = TimeSpan.Zero,
        NameClaimType = Claims.Name,
        RoleClaimType = Claims.Role,
        TypeValidator = static (type, token, parameters) =>
        {
            // Assume that tokens that don't have an explicit "typ" header attached are generic JSON Web Tokens.
            if (string.IsNullOrEmpty(type))
            {
                type = JsonWebTokenTypes.GenericJsonWebToken;
            }

            // Note: unlike IdentityModel, this custom validator deliberately uses case-insensitive comparisons.
            if (parameters.ValidTypes is not null && parameters.ValidTypes.Any() &&
               !parameters.ValidTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
            {
                throw new SecurityTokenInvalidTypeException(SR.GetResourceString(SR.ID0271))
                {
                    InvalidType = type
                };
            }

            return type;
        },
        // Note: audience and lifetime are manually validated by OpenIddict itself.
        ValidateAudience = false,
        ValidateLifetime = false
    };

    /// <summary>
    /// Gets the list of scopes sent by default as part of
    /// authorization requests and device authorization requests.
    /// </summary>
    public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the bag used to store additional provider-specific properties.
    /// </summary>
    public Dictionary<string, object?> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);
}
