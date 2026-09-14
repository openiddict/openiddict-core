/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

/// <summary>
/// Provides various settings needed to configure the OpenIddict server handler.
/// </summary>
public sealed class OpenIddictServerOptions
{
    /// <summary>
    /// Gets or sets the optional URI used to uniquely identify the authorization server.
    /// The URI must be absolute and may contain a path, but no query string or fragment part.
    /// </summary>
    public Uri? Issuer { get; set; }

    /// <summary>
    /// Gets the list of encryption credentials used by the OpenIddict server services.
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
    public List<EncryptingCredentials> EncryptionCredentials { get; } = [];

    /// <summary>
    /// Gets the list of signing credentials used by the OpenIddict server services.
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
    public List<SigningCredentials> SigningCredentials { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the authorization endpoint.
    /// </summary>
    public List<Uri> AuthorizationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the backchannel authentication endpoint.
    /// </summary>
    public List<Uri> BackchannelAuthenticationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the configuration endpoint.
    /// </summary>
    public List<Uri> ConfigurationEndpointUris { get; } =
    [
        new Uri(".well-known/openid-configuration", UriKind.Relative),
        new Uri(".well-known/oauth-authorization-server", UriKind.Relative)
    ];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the device authorization endpoint.
    /// </summary>
    public List<Uri> DeviceAuthorizationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the end session endpoint.
    /// </summary>
    public List<Uri> EndSessionEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the introspection endpoint.
    /// </summary>
    public List<Uri> IntrospectionEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the JSON Web Key Set endpoint.
    /// </summary>
    public List<Uri> JsonWebKeySetEndpointUris { get; } =
    [
        new Uri(".well-known/jwks", UriKind.Relative)
    ];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the pushed authorization endpoint.
    /// </summary>
    public List<Uri> PushedAuthorizationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the dynamic client registration endpoint.
    /// </summary>
    public List<Uri> RegistrationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the revocation endpoint.
    /// </summary>
    public List<Uri> RevocationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the token endpoint.
    /// </summary>
    public List<Uri> TokenEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the userinfo endpoint.
    /// </summary>
    public List<Uri> UserInfoEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the end-user verification endpoint.
    /// </summary>
    public List<Uri> EndUserVerificationEndpointUris { get; } = [];

    /// <summary>
    /// Gets or sets the JWT handler used to protect and unprotect tokens.
    /// </summary>
    public JsonWebTokenHandler JsonWebTokenHandler { get; set; } = new()
    {
        SetDefaultTimesOnTokenCreation = false
    };

    /// <summary>
    /// Gets or sets the URI listed as the mTLS device authorization
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    public Uri? MtlsDeviceAuthorizationEndpointAliasUri { get; set; }

    /// <summary>
    /// Gets or sets the URI listed as the mTLS introspection
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    public Uri? MtlsIntrospectionEndpointAliasUri { get; set; }

    /// <summary>
    /// Gets or sets the URI listed as the mTLS pushed authorization
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    public Uri? MtlsPushedAuthorizationEndpointAliasUri { get; set; }

    /// <summary>
    /// Gets or sets the URI listed as the mTLS revocation
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    public Uri? MtlsRevocationEndpointAliasUri { get; set; }

    /// <summary>
    /// Gets or sets the URI listed as the mTLS token
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    public Uri? MtlsTokenEndpointAliasUri { get; set; }

    /// <summary>
    /// Gets or sets the URI listed as the mTLS token
    /// endpoint alias in the server configuration metadata.
    /// </summary>
    /// <remarks>
    /// Note: this URI MUST be absolute and MUST point to a domain for
    /// which TLS client authentication is enforced by the web server.
    /// </remarks>
    public Uri? MtlsUserInfoEndpointAliasUri { get; set; }

    /// <summary>
    /// Gets the token validation parameters used by the OpenIddict server services.
    /// </summary>
    public TokenValidationParameters TokenValidationParameters { get; } = new()
    {
        AuthenticationType = TokenValidationParameters.DefaultAuthenticationType,
        ClockSkew = TimeSpan.Zero,
        NameClaimType = OpenIddictConstants.Claims.Name,
        RoleClaimType = OpenIddictConstants.Claims.Role,
        // In previous versions of OpenIddict (1.x and 2.x), all the JWT tokens (access and identity tokens)
        // were issued with the generic "typ": "JWT" header. To prevent confused deputy and token substitution
        // attacks, a special "token_usage" claim was added to the JWT payload to convey the actual token type.
        // This validator overrides the default logic used by IdentityModel to resolve the type from this claim.
        TypeValidator = static (type, token, parameters) =>
        {
            // If available, try to resolve the actual type from the "token_usage" claim.
            if (((JsonWebToken) token).TryGetPayloadValue(OpenIddictConstants.Claims.TokenUsage, out string usage))
            {
                type = usage switch
                {
                    "access_token" => JsonWebTokenTypes.AccessToken,
                    "id_token"     => JsonWebTokenTypes.GenericJsonWebToken,

                    _ => throw new NotSupportedException(SR.GetResourceString(SR.ID0269))
                };
            }

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
    /// Gets or sets the period of time authorization codes remain valid after being issued. The default value is 5 minutes.
    /// While not recommended, this property can be set to <see langword="null"/> to issue authorization codes that never expire.
    /// </summary>
    public TimeSpan? AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the period of time access tokens remain valid after being issued. The default value is 1 hour.
    /// The client application is expected to refresh or acquire a new access token after the token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue access tokens that never expire.
    /// </summary>
    public TimeSpan? AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the period of time authentication request identifiers (auth_req_id) returned by the backchannel
    /// authentication endpoint remain valid after being issued. The default value is 5 minutes. While not recommended,
    /// this property can be set to <see langword="null"/> to issue authentication request identifiers that never expire.
    /// </summary>
    public TimeSpan? AuthenticationRequestIdLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the minimum period of time client applications must wait between two polling token requests made
    /// using the device code or the Client-Initiated Backchannel Authentication grants. The default value is 5 seconds.
    /// Token requests sent before this period has elapsed are rejected with a "slow_down" error. If this property is
    /// set to <see langword="null"/>, the polling interval is neither returned to the client nor enforced.
    /// </summary>
    public TimeSpan? PollingInterval { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets the Client-Initiated Backchannel Authentication token delivery modes enabled for this server.
    /// By default, only the "poll" mode is enabled. The "ping" and "push" modes require registering
    /// a notification transport (e.g using the OpenIddict.Server.SystemNetHttp integration package).
    /// </summary>
    /// <remarks>
    /// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.5.
    /// </remarks>
    public HashSet<string> BackchannelTokenDeliveryModes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.BackchannelTokenDeliveryModes.Poll
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether signed authentication requests (sent using the "request"
    /// parameter, as defined by the CIBA specification) are accepted by the backchannel authentication endpoint.
    /// </summary>
    public bool EnableSignedBackchannelAuthenticationRequests { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the "user_code" parameter is supported
    /// by the backchannel authentication endpoint. When enabled, client applications registered
    /// with the <see cref="OpenIddictConstants.Settings.BackchannelAuthentication.UserCodeParameter"/>
    /// setting must send a user code, whose value must be validated by the application.
    /// </summary>
    public bool EnableBackchannelUserCodeParameter { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of times a failed ping or push notification is retried.
    /// The default value is 2.
    /// </summary>
    public int BackchannelNotificationRetryCount { get; set; } = 2;

    /// <summary>
    /// Gets or sets the delay applied between two ping or push notification attempts.
    /// The default value is 1 second.
    /// </summary>
    public TimeSpan BackchannelNotificationRetryDelay { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Gets or sets the period of time device codes remain valid after being issued. The default value is 10 minutes.
    /// The client application is expected to start a whole new authentication flow after the device code has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue device codes that never expire.
    /// Note: the same value should be chosen for both <see cref="UserCodeLifetime"/> and this property.
    /// </summary>
    /// <remarks>
    /// The expiration date of a device code is automatically extended when the user approves the
    /// authorization demand to give the client application enough time to redeem the device code.
    /// </remarks>
    public TimeSpan? DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets or sets the period of time identity tokens remain valid after being issued. The default value is 20 minutes.
    /// The client application is expected to refresh or acquire a new identity token after the token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue identity tokens that never expire.
    /// </summary>
    public TimeSpan? IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(20);

    /// <summary>
    /// Gets or sets the period of time issued tokens remain valid after being issued. The default value is 1 hour.
    /// The client application is expected to refresh or acquire a new issued token after the token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue issued tokens that never expire.
    /// </summary>
    /// <remarks>
    /// Note: this property is not used when the requested token type is recognized and matches a token type internally
    /// supported (e.g access token): in that case, the dedicated lifetime option is used instead of this value.
    /// </remarks>
    public TimeSpan? IssuedTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the period of time request tokens remain valid after being issued. The default value is 1 hour.
    /// The client application is expected to start a whole new authentication flow after the request token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue request tokens that never expire.
    /// </summary>
    public TimeSpan? RequestTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the period of time refresh tokens remain valid after being issued. The default value is 14 days.
    /// The client application is expected to start a whole new authentication flow after the refresh token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue refresh tokens that never expire.
    /// </summary>
    public TimeSpan? RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the period of time rolling refresh tokens marked as redeemed can still be
    /// used to make concurrent refresh token requests. The default value is 30 seconds.
    /// </summary>
    public TimeSpan? RefreshTokenReuseLeeway { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets the charset used by OpenIddict to generate random user codes.
    /// </summary>
    /// <remarks>
    /// Note: user codes are meant to be used by humans, who may have to type them manually.
    /// To ensure they remain easy enough to type even by users with non-Latin keyboards,
    /// user codes generated by OpenIddict only include ASCII digits by default.
    /// </remarks>
    public HashSet<string> UserCodeCharset { get; } = new(StringComparer.Ordinal)
    {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"
    };

    /// <summary>
    /// Gets or sets the format string used by OpenIddict to display user codes. While not recommended,
    /// a <see langword="null"/> value can be used to disable the user code formatting logic.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, a default format using dash separators
    /// is used to make user codes easier to read by the end users.
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public string? UserCodeDisplayFormat { get; set; }

    /// <summary>
    /// Gets or sets the length of the user codes generated by OpenIddict (by default, 12 characters).
    /// </summary>
    public int UserCodeLength { get; set; } = 12;

    /// <summary>
    /// Gets or sets the period of time user codes remain valid after being issued. The default value is 10 minutes.
    /// The client application is expected to start a whole new authentication flow after the user code has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue user codes that never expire.
    /// Note: the same value should be chosen for both <see cref="DeviceCodeLifetime"/> and this property.
    /// </summary>
    public TimeSpan? UserCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets or sets a boolean indicating whether the degraded mode is enabled. When this degraded mode
    /// is enabled, all the security checks that depend on the OpenIddict core managers are disabled.
    /// This option MUST be enabled with extreme caution and custom handlers MUST be registered to
    /// properly validate OpenID Connect requests.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public bool EnableDegradedMode { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether signing and encryption keys are automatically
    /// created, rotated and retired using the key store (in addition to the static credentials).
    /// </summary>
    public bool EnableAutomaticKeyManagement { get; set; }

    /// <summary>
    /// Gets or sets the period during which an automatically managed key is used to protect tokens (by default, 90 days).
    /// </summary>
    public TimeSpan KeyRotationInterval { get; set; } = TimeSpan.FromDays(90);

    /// <summary>
    /// Gets or sets the period during which a new automatically managed key is published before being used (by default, 14 days).
    /// </summary>
    public TimeSpan KeyPropagationTime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the period during which an expired automatically managed key is still published (by default, 14 days).
    /// </summary>
    public TimeSpan KeyRetentionTime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the maximum period during which the automatically managed keys are cached (by default, 1 hour).
    /// </summary>
    public TimeSpan KeyRingCacheLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets the list of the handlers responsible for processing the OpenIddict server operations.
    /// Note: the list is automatically sorted based on the order assigned to each handler descriptor.
    /// As such, it MUST NOT be mutated after options initialization to preserve the exact order.
    /// </summary>
    public List<OpenIddictServerHandlerDescriptor> Handlers { get; } = [.. OpenIddictServerHandlers.DefaultHandlers];

    /// <summary>
    /// Gets or sets a boolean determining whether client identification is optional.
    /// Enabling this option allows client applications to communicate with the token,
    /// introspection and revocation endpoints without having to send their client identifier.
    /// </summary>
    /// <remarks>
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </remarks>
    public bool AcceptAnonymousClients { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect claims supported by this application.
    /// </summary>
    public HashSet<string> Claims { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.Claims.Audience,
        OpenIddictConstants.Claims.ExpiresAt,
        OpenIddictConstants.Claims.IssuedAt,
        OpenIddictConstants.Claims.Issuer,
        OpenIddictConstants.Claims.Subject
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether access token encryption should be disabled.
    /// Disabling encryption is NOT recommended and SHOULD only be done when issuing tokens
    /// to third-party resource servers/APIs you don't control and don't fully trust.
    /// Note: disabling encryption has no effect when using ASP.NET Core Data Protection.
    /// </summary>
    public bool DisableAccessTokenEncryption { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether authorization storage should be disabled.
    /// When disabled, ad-hoc authorizations are not created when an authorization code or
    /// refresh token is issued and can't be revoked to prevent associated tokens from being used.
    /// </summary>
    public bool DisableAuthorizationStorage { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether rolling tokens are disabled.
    /// When disabled, refresh tokens used in a token request are not marked
    /// as redeemed and can still be used until they expire. Disabling
    /// rolling refresh tokens is NOT recommended, for security reasons.
    /// </summary>
    public bool DisableRollingRefreshTokens { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether sliding expiration is disabled
    /// for refresh tokens. When this option is set to <see langword="true"/>,
    /// refresh tokens are issued with a fixed expiration date: when they expire,
    /// a complete authorization flow must be started to retrieve a new refresh token.
    /// </summary>
    public bool DisableSlidingRefreshTokenExpiration { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether token storage should be disabled.
    /// When disabled, no database entry is created for the tokens and codes
    /// returned by OpenIddict. Using this option is generally NOT recommended
    /// as it prevents the tokens and codes from being revoked (if needed).
    /// </summary>
    /// <remarks>
    /// Note: disabling token storage prevents the device authorization flow
    /// from being used and automatically turns sliding expiration off.
    /// </remarks>
    public bool DisableTokenStorage { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether audience validation is disabled.
    /// </summary>
    public bool DisableAudienceValidation { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether resource validation is disabled.
    /// </summary>
    public bool DisableResourceValidation { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether scope validation is disabled.
    /// </summary>
    public bool DisableScopeValidation { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether requests received by the authorization
    /// endpoint should be stored in the token store, which allows flowing
    /// large payloads across requests. Enabling this option can be useful
    /// for clients that do not supported pushed authorization requests.
    /// </summary>
    public bool EnableAuthorizationRequestCaching { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether requests received
    /// by the end session endpoint should be stored in the token store.
    /// </summary>
    public bool EnableEndSessionRequestCaching { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0 token exchange actor token types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> ActorTokenTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.TokenTypeIdentifiers.AccessToken,
        OpenIddictConstants.TokenTypeIdentifiers.IdentityToken,
        OpenIddictConstants.TokenTypeIdentifiers.RefreshToken
    };

    /// <summary>
    /// Gets the OAuth 2.0 audiences enabled for this application
    /// (exclusively used with the OAuth 2.0 Token Exchange flow).
    /// </summary>
    public HashSet<string> Audiences { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OAuth 2.0 client assertion types enabled for this application.
    /// </summary>
    public HashSet<string> ClientAssertionTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.ClientAssertionTypes.JwtBearer
    };

    /// <summary>
    /// Gets the OAuth 2.0 client authentication methods enabled for this application.
    /// </summary>
    public HashSet<string> ClientAuthenticationMethods { get; } = new(StringComparer.Ordinal)
    {
        // Note: client_secret_basic is deliberately not added here as it requires
        // a dedicated event handler (typically provided by the host integration)
        // to extract the client credentials from the standard Authorization header.
        //
        // Both the ASP.NET Core and OWIN hosts support the client_secret_basic
        // authentication method and automatically add it to this list at runtime.
        OpenIddictConstants.ClientAuthenticationMethods.ClientSecretPost,
        OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt
    };

    /// <summary>
    /// Gets the OAuth 2.0 code challenge methods enabled for this application.
    /// </summary>
    public HashSet<string> CodeChallengeMethods { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.CodeChallengeMethods.Plain,
        OpenIddictConstants.CodeChallengeMethods.Sha256
    };

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect flows enabled for this application.
    /// </summary>
    public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OpenID Connect prompt values enabled for this application.
    /// </summary>
    public HashSet<string> PromptValues { get; } = new(StringComparer.Ordinal)
    {
        // By default, only include the mandatory values defined in the core OpenID Connect specification.
        // See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest for more information.
        OpenIddictConstants.PromptValues.Consent,
        OpenIddictConstants.PromptValues.Login,
        OpenIddictConstants.PromptValues.None,
        OpenIddictConstants.PromptValues.SelectAccount
    };

    /// <summary>
    /// Gets the OAuth 2.0 token exchange requested token types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> RequestedTokenTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.TokenTypeIdentifiers.AccessToken
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether PKCE must be used by client applications
    /// when requesting an authorization code (e.g when using the code or hybrid flows).
    /// If this property is set to <see langword="true"/>, authorization requests that
    /// lack the code_challenge will be automatically rejected by OpenIddict.
    /// </summary>
    public bool RequireProofKeyForCodeExchange { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether pushed authorization requests must be used
    /// by client applications when using an interactive flow like the authorization code or
    /// implicit flows. If this property is set to <see langword="true"/>, authorization requests
    /// that don't contain a request_uri parameter will be automatically rejected by OpenIddict.
    /// </summary>
    public bool RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether authorization and pushed authorization requests
    /// must be sent as signed request objects using the "request" parameter. If this property
    /// is set to <see langword="true"/>, requests that don't contain a request object are rejected.
    /// </summary>
    /// <remarks>
    /// Note: this option requires enabling request object support using <see cref="EnableRequestObjectSupport"/>.
    /// </remarks>
    public bool RequireSignedRequestObjects { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether JWT-secured authorization requests (i.e request objects
    /// sent using the "request" parameter, as defined by RFC 9101) are accepted by the authorization and
    /// pushed authorization endpoints. Request objects must be signed using a key present in the JSON Web
    /// Key Set attached to the client application and may optionally be encrypted using one of the
    /// encryption credentials registered in the server options.
    /// </summary>
    public bool EnableRequestObjectSupport { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether OAuth 2.0 Demonstrating Proof of Possession (DPoP, RFC 9449)
    /// is supported. When enabled, DPoP proofs sent to the token, pushed authorization and userinfo endpoints
    /// are validated and access tokens (and refresh tokens issued to public clients) are bound to the proof key.
    /// </summary>
    public bool EnableDPoPSupport { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether JSON Web Token introspection responses (RFC 9701) are supported.
    /// When enabled, introspection requests that include an "Accept: application/token-introspection+jwt"
    /// header receive a signed JWT whose "token_introspection" claim contains the introspection response.
    /// The JWT is also encrypted if the client application opted in using the
    /// <see cref="Settings.IntrospectionResponse.EncryptionAlgorithm"/> setting (the only supported value
    /// is "RSA-OAEP") and has an RSA encryption key ("use": "enc") in its JSON Web Key Set.
    /// </summary>
    public bool EnableJsonWebTokenIntrospectionResponses { get; set; }

    /// <summary>
    /// Gets the absolute and relative URIs associated to the check session iframe endpoint
    /// defined by OpenID Connect Session Management 1.0. Only used when
    /// <see cref="EnableSessionManagement"/> is set to <see langword="true"/>.
    /// </summary>
    public List<Uri> CheckSessionIframeEndpointUris { get; } = [];

    /// <summary>
    /// Gets or sets a boolean indicating whether OpenID Connect Back-Channel Logout 1.0 is enabled.
    /// When enabled, a logout token is sent to the back-channel logout URI of each client application
    /// that participated in a session terminated by the end session endpoint or by <see cref="OpenIddictServerService"/>.
    /// </summary>
    /// <remarks>
    /// Note: a transport must be registered (e.g using <c>UseSystemNetHttp()</c> from the
    /// OpenIddict.Server.SystemNetHttp package) to send the back-channel logout requests.
    /// </remarks>
    public bool EnableBackchannelLogout { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether OpenID Connect Front-Channel Logout 1.0 is enabled.
    /// When enabled, the front-channel logout URIs of the client applications that participated
    /// in a session terminated by the end session endpoint are rendered as iframes by the host.
    /// </summary>
    public bool EnableFrontchannelLogout { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether OpenID Connect Session Management 1.0 is enabled
    /// (check session iframe endpoint and "session_state" authorization response parameter).
    /// </summary>
    public bool EnableSessionManagement { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the session attached to a sign-out
    /// demand processed by the end session endpoint (and all the sessions sharing the same
    /// login identifier) should be revoked, alongside the tokens attached to these sessions.
    /// </summary>
    public bool EnableSessionRevocationOnSignOut { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the standard "sid" claim should be added to access tokens
    /// when a session is attached to the sign-in demand (identity tokens always include it).
    /// </summary>
    public bool IncludeSessionIdInAccessTokens { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether a server-side session entry should be automatically created
    /// (or reused) for sign-in demands processed by the authorization endpoint that don't already specify a session.
    /// The login identifier used to correlate the sessions of the same end-user authentication across client applications
    /// can be specified by the host using the <see cref="OpenIddictConstants.Properties.LoginId"/> sign-in property.
    /// </summary>
    public bool EnableAutomaticSessionCreation { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the session terminated by the end session endpoint can be resolved
    /// from the "sid" claim of the identity token hint when the host doesn't specify it using the
    /// <see cref="OpenIddictConstants.Properties.SessionId"/> sign-out property.
    /// </summary>
    /// <remarks>
    /// Caution: an identity token hint doesn't prove that the session belongs to the user currently authenticated
    /// at the authorization server: any party holding an identity token (e.g the client application it was issued to)
    /// can use it to terminate the session and log the user out of all the client applications that participated in it.
    /// </remarks>
    public bool EnableIdentityTokenHintSessionResolution { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether the authorization attached to a
    /// terminated session should also be revoked when the session is terminated.
    /// </summary>
    public bool RevokeAuthorizationsOnSessionTermination { get; set; }

    /// <summary>
    /// Gets or sets the maximum amount of time allowed to send a back-channel logout request (by default, 5 seconds).
    /// </summary>
    public TimeSpan BackchannelLogoutTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Gets or sets the lifetime of the logout tokens sent to the back-channel logout URIs (by default, 2 minutes).
    /// </summary>
    public TimeSpan LogoutTokenLifetime { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Gets or sets the name of the cookie storing the OP browser state used by
    /// OpenID Connect Session Management 1.0 (by default, "openiddict.browser_state").
    /// </summary>
    public string BrowserStateCookieName { get; set; } = "openiddict.browser_state";

    /// <summary>
    /// Gets or sets the idle timeout applied to sessions: when set, the expiration date of the session
    /// attached to a sign-in demand is extended to the current date plus this value (sliding expiration).
    /// </summary>
    public TimeSpan? SessionIdleTimeout { get; set; }

    /// <summary>
    /// Gets or sets the absolute lifetime of sessions, computed from their creation date: when set,
    /// the expiration date of the session attached to a sign-in demand never exceeds this limit.
    /// </summary>
    public TimeSpan? SessionLifetime { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether JWT Secured Authorization Response Modes (JARM) are supported.
    /// When enabled, the "jwt", "query.jwt", "fragment.jwt" and "form_post.jwt" response modes can be used
    /// (as long as the corresponding "query", "fragment" or "form_post" response mode is also enabled) and
    /// the authorization response parameters are returned in a signed JWT sent using the "response" parameter.
    /// The JWT is also encrypted if the client application opted in using the
    /// <see cref="Settings.AuthorizationResponse.EncryptionAlgorithm"/> setting.
    /// </summary>
    public bool EnableJwtSecuredAuthorizationResponses { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether authorization and pushed authorization requests
    /// must use one of the JWT Secured Authorization Response Modes (JARM).
    /// </summary>
    /// <remarks>
    /// Note: this option requires enabling JARM support using <see cref="EnableJwtSecuredAuthorizationResponses"/>.
    /// </remarks>
    public bool RequireJwtSecuredAuthorizationResponses { get; set; }

    /// <summary>
    /// Gets or sets the period of time JWT authorization responses (JARM) remain valid after being issued.
    /// The default value is 5 minutes. As required by the JARM specification, the "exp" claim is always
    /// included in the JWT and this value cannot be <see langword="null"/>.
    /// </summary>
    public TimeSpan AuthorizationResponseLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets a boolean indicating whether all token requests must include a valid DPoP proof.
    /// </summary>
    /// <remarks>
    /// Note: this option requires enabling DPoP support using <see cref="EnableDPoPSupport"/>.
    /// </remarks>
    public bool RequireDPoP { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether DPoP proofs must include a server-provided nonce.
    /// </summary>
    /// <remarks>
    /// Note: this option requires enabling DPoP support using <see cref="EnableDPoPSupport"/>.
    /// </remarks>
    public bool RequireDPoPNonces { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether OAuth 2.0 Dynamic Client Registration (RFC 7591) and
    /// Dynamic Client Registration Management (RFC 7592) are enabled. When enabled, the registration
    /// endpoint creates, reads, updates and deletes client applications using the application manager.
    /// </summary>
    /// <remarks>
    /// Note: this option requires setting at least one registration endpoint URI.
    /// </remarks>
    public bool EnableDynamicClientRegistration { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether client registration requests that don't include an initial
    /// access token are accepted. Setting this property to <see langword="true"/> enables open registration
    /// and is NOT recommended unless additional policy handlers are registered to approve registrations.
    /// </summary>
    public bool AllowAnonymousClientRegistration { get; set; }

    /// <summary>
    /// Gets the scopes that initial access tokens must contain (at least one of them) to be accepted
    /// by the registration endpoint. Initial access tokens are access tokens issued by this server.
    /// </summary>
    public HashSet<string> InitialAccessTokenScopes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the period of time registration access tokens (RFC 7592) remain valid after being issued.
    /// By default, registration access tokens don't expire and remain valid until the client is deleted.
    /// </summary>
    public TimeSpan? RegistrationAccessTokenLifetime { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether client registration requests must include a software statement.
    /// </summary>
    public bool RequireSoftwareStatement { get; set; }

    /// <summary>
    /// Gets the issuers whose software statements are accepted by the registration endpoint.
    /// If no issuer is added, any issuer is accepted, as long as the software statement
    /// is signed by one of the keys listed in <see cref="SoftwareStatementSigningKeys"/>.
    /// </summary>
    public HashSet<string> SoftwareStatementIssuers { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the keys trusted to sign the software statements sent to the registration endpoint.
    /// If no key is added, software statements are always rejected as unapproved.
    /// </summary>
    public List<SecurityKey> SoftwareStatementSigningKeys { get; } = [];

    /// <summary>
    /// Gets the grant types dynamically registered client applications are allowed to use (in addition to
    /// being enabled in the server options). By default, the authorization code, implicit, refresh token,
    /// client credentials, device authorization and CIBA grants are allowed: grants that require a higher
    /// level of trust (e.g password or token exchange) must be explicitly added to be registrable.
    /// </summary>
    public HashSet<string> RegistrationAllowedGrantTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.GrantTypes.AuthorizationCode,
        OpenIddictConstants.GrantTypes.Ciba,
        OpenIddictConstants.GrantTypes.ClientCredentials,
        OpenIddictConstants.GrantTypes.DeviceCode,
        OpenIddictConstants.GrantTypes.Implicit,
        OpenIddictConstants.GrantTypes.RefreshToken
    };

    /// <summary>
    /// Gets the scopes dynamically registered client applications are allowed to request. If no scope is
    /// added, all the registered scopes can be requested. Note: the scopes listed in
    /// <see cref="InitialAccessTokenScopes"/> can never be requested by dynamically registered clients.
    /// </summary>
    public HashSet<string> RegistrationAllowedScopes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the maximum difference allowed between the issuance date of a DPoP proof and the current date.
    /// </summary>
    public TimeSpan DPoPProofLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the lifetime of the DPoP nonces issued when <see cref="RequireDPoPNonces"/> is enabled.
    /// </summary>
    public TimeSpan DPoPNonceLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets the asymmetric signing algorithms allowed for DPoP proofs.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> DPoPSigningAlgorithms { get; } = new(StringComparer.Ordinal)
    {
        SecurityAlgorithms.EcdsaSha256,
        SecurityAlgorithms.EcdsaSha384,
        SecurityAlgorithms.EcdsaSha512,
        SecurityAlgorithms.RsaSha256,
        SecurityAlgorithms.RsaSha384,
        SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256,
        SecurityAlgorithms.RsaSsaPssSha384,
        SecurityAlgorithms.RsaSsaPssSha512
    };

    /// <summary>
    /// Gets the OAuth 2.0 resources enabled for this application (typically used
    /// with the OAuth 2.0 Token Exchange flow and with authorization or pushed
    /// authorization requests that include one or more resource indicators).
    /// </summary>
    public HashSet<Uri> Resources { get; } = [];

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect response types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect response modes enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> ResponseModes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.ResponseModes.FormPost,
        OpenIddictConstants.ResponseModes.Fragment,
        OpenIddictConstants.ResponseModes.Query
    };

    /// <summary>
    /// Gets the OAuth 2.0 token exchange subject token types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> SubjectTokenTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.TokenTypeIdentifiers.AccessToken,
        OpenIddictConstants.TokenTypeIdentifiers.IdentityToken,
        OpenIddictConstants.TokenTypeIdentifiers.RefreshToken
    };

    /// <summary>
    /// Gets the OpenID Connect subject types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> SubjectTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.SubjectTypes.Public
    };

    /// <summary>
    /// Gets or sets the default token type that is used as the requested token type when no
    /// explicit value is requested by the client during an OAuth 2.0 token exchange flow.
    /// </summary>
    /// <remarks>
    /// By default, an access token is always returned when no explicit value is requested.
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public string DefaultRequestedTokenType { get; set; } = TokenTypeIdentifiers.AccessToken;

    /// <summary>
    /// Gets or sets a boolean indicating whether audience permissions should be ignored.
    /// </summary>
    /// <remarks>
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </remarks>
    public bool IgnoreAudiencePermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether endpoint permissions should be ignored.
    /// </summary>
    /// <remarks>
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </remarks>
    public bool IgnoreEndpointPermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether grant type permissions should be ignored.
    /// </summary>
    /// <remarks>
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </remarks>
    public bool IgnoreGrantTypePermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether resource permissions should be ignored.
    /// </summary>
    /// <remarks>
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </remarks>
    public bool IgnoreResourcePermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether response type permissions should be ignored.
    /// </summary>
    /// <remarks>
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </remarks>
    public bool IgnoreResponseTypePermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether scope permissions should be ignored.
    /// </summary>
    /// <remarks>
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </remarks>
    public bool IgnoreScopePermissions { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect scopes enabled for this application.
    /// </summary>
    public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.Scopes.OpenId
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether reference access tokens should be used.
    /// When set to <see langword="true"/>, the token payload is stored in the database
    /// and a crypto-secure random identifier is returned to the client application.
    /// Enabling this option is useful when storing a very large number of claims
    /// in the tokens, but it is RECOMMENDED to enable column encryption
    /// in the database or use the ASP.NET Core Data Protection integration,
    /// that provides additional protection against token leakage.
    /// </summary>
    public bool UseReferenceAccessTokens { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether reference refresh tokens should be used.
    /// When set to <see langword="true"/>, the token payload is stored in the database
    /// and a crypto-secure random identifier is returned to the client application.
    /// Enabling this option is useful when storing a very large number of claims
    /// in the tokens, but it is RECOMMENDED to enable column encryption
    /// in the database or use the ASP.NET Core Data Protection integration,
    /// that provides additional protection against token leakage.
    /// </summary>
    public bool UseReferenceRefreshTokens { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether access tokens should be bound to the
    /// client certificate sent by public or confidential clients in the TLS handshake
    /// of token requests.
    /// </summary>
    public bool UseClientCertificateBoundAccessTokens { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether access tokens should be bound to the
    /// client certificate sent by public clients in the TLS handshake of token requests.
    /// </summary>
    /// <remarks>
    /// Note: refresh tokens are only bound to the client certificate when the client
    /// is a public application, as refresh tokens issued to confidential applications
    /// are already sender-constrained via standard client authentication.
    /// </remarks>
    public bool UseClientCertificateBoundRefreshTokens { get; set; }

    /// <summary>
    /// Gets or sets the time provider.
    /// </summary>
    /// <remarks>
    /// Note: if this property is not explicitly set, the time provider is
    /// automatically resolved from the dependency injection container.
    /// If no service can be found, <see cref="TimeProvider.System"/> is used.
    /// </remarks>
    public TimeProvider TimeProvider { get; set; } = default!;

    /// <summary>
    /// Gets or sets the chain policy used when validating PKI
    /// client certificates used for OAuth 2.0 client authentication.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Note: this instance serves as a base policy and is merged with
    /// the per-client policies resolved using the application manager.
    /// </para>
    /// <para>
    /// Note: while it is possible to use a policy configured to use the
    /// the system certificates store, doing so is strongly discouraged.
    /// </para>
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public X509ChainPolicy? PublicKeyInfrastructureTlsClientAuthenticationPolicy { get; set; }

    /// <summary>
    /// Gets or sets the chain policy used when validating self-signed client
    /// certificates used for OAuth 2.0 client authentication and/or token binding.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Note: this instance serves as a base policy and is merged with
    /// the per-client policies resolved using the application manager.
    /// </para>
    /// <para>
    /// Note: while it is possible to use a policy configured to use the
    /// the system certificates store, doing so is strongly discouraged.
    /// </para>
    /// </remarks>
    public X509ChainPolicy? SelfSignedTlsClientAuthenticationPolicy { get; set; }
}
