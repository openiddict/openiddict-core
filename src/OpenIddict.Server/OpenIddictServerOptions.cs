/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict server handler.
    /// </summary>
    public class OpenIddictServerOptions
    {
        /// <summary>
        /// Gets or sets the optional base address used to uniquely identify the authorization server.
        /// The URI must be absolute and may contain a path, but no query string or fragment part.
        /// </summary>
        public Uri Issuer { get; set; }

        /// <summary>
        /// Gets the list of credentials used to encrypt the tokens issued by the
        /// OpenIddict server services. Note: the encryption credentials are not
        /// used to protect/unprotect tokens issued by ASP.NET Core Data Protection.
        /// </summary>
        public List<EncryptingCredentials> EncryptionCredentials { get; } = new List<EncryptingCredentials>();

        /// <summary>
        /// Gets the list of credentials used to sign the tokens issued by the OpenIddict server services.
        /// Both asymmetric and symmetric keys are supported, but only asymmetric keys can be used to sign identity tokens.
        /// Note that only asymmetric RSA and ECDSA keys can be exposed by the JWKS metadata endpoint and that the
        /// signing credentials are not used to protect/unprotect tokens issued by ASP.NET Core Data Protection.
        /// </summary>
        public List<SigningCredentials> SigningCredentials { get; } = new List<SigningCredentials>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the authorization endpoint.
        /// </summary>
        public List<Uri> AuthorizationEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the configuration endpoint.
        /// </summary>
        public List<Uri> ConfigurationEndpointUris { get; } = new List<Uri>
        {
            new Uri("/.well-known/openid-configuration", UriKind.Relative),
            new Uri("/.well-known/oauth-authorization-server", UriKind.Relative)
        };

        /// <summary>
        /// Gets the absolute and relative URIs associated to the cryptography endpoint.
        /// </summary>
        public List<Uri> CryptographyEndpointUris { get; } = new List<Uri>
        {
            new Uri("/.well-known/jwks", UriKind.Relative)
        };

        /// <summary>
        /// Gets the absolute and relative URIs associated to the device endpoint.
        /// </summary>
        public List<Uri> DeviceEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the introspection endpoint.
        /// </summary>
        public List<Uri> IntrospectionEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the logout endpoint.
        /// </summary>
        public List<Uri> LogoutEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the revocation endpoint.
        /// </summary>
        public List<Uri> RevocationEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the token endpoint.
        /// </summary>
        public List<Uri> TokenEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the userinfo endpoint.
        /// </summary>
        public List<Uri> UserinfoEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the verification endpoint.
        /// </summary>
        public List<Uri> VerificationEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets or sets the JWT handler used to protect and unprotect tokens.
        /// </summary>
        public JsonWebTokenHandler JsonWebTokenHandler { get; set; } = new JsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };

        /// <summary>
        /// Gets the token validation parameters used by the OpenIddict server services.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; } = new TokenValidationParameters
        {
            AuthenticationType = TokenValidationParameters.DefaultAuthenticationType,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = OpenIddictConstants.Claims.Name,
            RoleClaimType = OpenIddictConstants.Claims.Role,
            // In previous versions of OpenIddict (1.x and 2.x), all the JWT tokens (access and identity tokens)
            // were issued with the generic "typ": "JWT" header. To prevent confused deputy and token substitution
            // attacks, a special "token_usage" claim was added to the JWT payload to convey the actual token type.
            // This validator overrides the default logic used by IdentityModel to resolve the type from this claim.
            TypeValidator = (type, token, parameters) =>
            {
                if (string.IsNullOrEmpty(type))
                {
                    throw new SecurityTokenInvalidTypeException("The 'typ' header of the JWT token cannot be null or empty.");
                }

                // If the generic type of the token is "JWT", try to resolve the actual type from the "token_usage" claim.
                if (string.Equals(type, JwtConstants.HeaderType, StringComparison.OrdinalIgnoreCase) &&
                   ((JsonWebToken) token).TryGetPayloadValue(OpenIddictConstants.Claims.TokenUsage, out string usage))
                {
                    type = usage switch
                    {
                        TokenTypeHints.AccessToken => JsonWebTokenTypes.AccessToken,
                        TokenTypeHints.IdToken     => JsonWebTokenTypes.IdentityToken,

                        _ => throw new NotSupportedException("The token usage of the JWT token is not supported.")
                    };
                }

                if (parameters.ValidTypes != null && parameters.ValidTypes.Any() &&
                   !parameters.ValidTypes.Contains(type, StringComparer.Ordinal))
                {
                    throw new SecurityTokenInvalidTypeException("The type of the JWT token doesn't match the expected type.");
                }

                return type;
            },
            // Note: audience and lifetime are manually validated by OpenIddict itself.
            ValidateAudience = false,
            ValidateLifetime = false,
            // Note: valid types can be overriden by OpenIddict depending on the received request.
            ValidTypes = new[]
            {
                JsonWebTokenTypes.AccessToken,
                JsonWebTokenTypes.IdentityToken,
                JsonWebTokenTypes.Private.AuthorizationCode,
                JsonWebTokenTypes.Private.DeviceCode,
                JsonWebTokenTypes.Private.RefreshToken,
                JsonWebTokenTypes.Private.UserCode
            }
        };

        /// <summary>
        /// Gets or sets the period of time authorization codes remain valid after being issued. The default value is 5 minutes.
        /// While not recommended, this property can be set to <c>null</c> to issue codes that never expire.
        /// </summary>
        public TimeSpan? AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Gets or sets the period of time access tokens remain valid after being issued. The default value is 1 hour.
        /// The client application is expected to refresh or acquire a new access token after the token has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue access tokens that never expire.
        /// </summary>
        public TimeSpan? AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// Gets or sets the period of time device codes remain valid after being issued. The default value is 10 minutes.
        /// The client application is expected to start a whole new authentication flow after the device code has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue codes that never expire.
        /// Note: the same value should be chosen for both <see cref="UserCodeLifetime"/> and this property.
        /// </summary>
        public TimeSpan? DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Gets or sets the period of time identity tokens remain valid after being issued. The default value is 20 minutes.
        /// The client application is expected to refresh or acquire a new identity token after the token has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue identity tokens that never expire.
        /// </summary>
        public TimeSpan? IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(20);

        /// <summary>
        /// Gets or sets the period of time refresh tokens remain valid after being issued. The default value is 14 days.
        /// The client application is expected to start a whole new authentication flow after the refresh token has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue refresh tokens that never expire.
        /// </summary>
        public TimeSpan? RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

        /// <summary>
        /// Gets or sets the period of time user codes remain valid after being issued. The default value is 10 minutes.
        /// The client application is expected to start a whole new authentication flow after the user code has expired.
        /// While not recommended, this property can be set to <c>null</c> to issue codes that never expire.
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
        /// Gets the list of the handlers responsible of processing the OpenIddict server operations.
        /// Note: the list is automatically sorted based on the order assigned to each handler descriptor.
        /// As such, it MUST NOT be mutated after options initialization to preserve the exact order.
        /// </summary>
        public List<OpenIddictServerHandlerDescriptor> Handlers { get; } =
            new List<OpenIddictServerHandlerDescriptor>(OpenIddictServerHandlers.DefaultHandlers);

        /// <summary>
        /// Gets or sets a boolean indicating whether new refresh tokens should be issued during a refresh token request.
        /// Set this property to <c>true</c> to issue a new refresh token, <c>false</c> to prevent OpenIddict
        /// from issuing new refresh tokens when receiving a grant_type=refresh_token request.
        /// </summary>
        public bool UseSlidingExpiration { get; set; } = true;

        /// <summary>
        /// Gets or sets a boolean determining whether client identification is optional.
        /// Enabling this option allows client applications to communicate with the token,
        /// introspection and revocation endpoints without having to send their client identifier.
        /// </summary>
        public bool AcceptAnonymousClients { get; set; }

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect claims supported by this application.
        /// </summary>
        public HashSet<string> Claims { get; } = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIddictConstants.Claims.Audience,
            OpenIddictConstants.Claims.ExpiresAt,
            OpenIddictConstants.Claims.IssuedAt,
            OpenIddictConstants.Claims.Issuer,
            OpenIddictConstants.Claims.JwtId,
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
        /// Gets or sets a boolean indicating whether token storage should be disabled.
        /// When disabled, no database entry is created for the tokens and codes
        /// returned by OpenIddict. Using this option is generally NOT recommended
        /// as it prevents the tokens and codes from being revoked (if needed).
        /// </summary>
        public bool DisableTokenStorage { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether scope validation is disabled.
        /// </summary>
        public bool DisableScopeValidation { get; set; }

        /// <summary>
        /// Gets the OAuth 2.0 code challenge methods enabled for this application.
        /// By default, only the S256 method is allowed (if the code flow is enabled).
        /// </summary>
        public HashSet<string> CodeChallengeMethods { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect flows enabled for this application.
        /// </summary>
        public HashSet<string> GrantTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect response types enabled for this application.
        /// Response types are automatically inferred from the supported standard grant types,
        /// but additional values can be added for advanced scenarios (e.g custom type support).
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public HashSet<string> ResponseTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect response modes enabled for this application.
        /// Response modes are automatically inferred from the supported standard grant types,
        /// but additional values can be added for advanced scenarios (e.g custom mode support).
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public HashSet<string> ResponseModes { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets a boolean indicating whether endpoint permissions should be ignored.
        /// Setting this property to <c>true</c> is NOT recommended, unless all
        /// the clients are first-party applications you own, control and fully trust.
        /// </summary>
        public bool IgnoreEndpointPermissions { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether grant type permissions should be ignored.
        /// Setting this property to <c>true</c> is NOT recommended, unless all
        /// the clients are first-party applications you own, control and fully trust.
        /// </summary>
        public bool IgnoreGrantTypePermissions { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether scope permissions should be ignored.
        /// Setting this property to <c>true</c> is NOT recommended, unless all
        /// the clients are first-party applications you own, control and fully trust.
        /// </summary>
        public bool IgnoreScopePermissions { get; set; }

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect scopes enabled for this application.
        /// </summary>
        public HashSet<string> Scopes { get; } = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIddictConstants.Scopes.OpenId
        };

        /// <summary>
        /// Gets or sets a boolean indicating whether reference access tokens should be used.
        /// When set to <c>true</c>, the token payload is stored in the database and a
        /// crypto-secure random identifier is returned to the client application.
        /// Enabling this option is useful when storing a very large number of claims
        /// in the tokens, but it is RECOMMENDED to enable column encryption
        /// in the database or use the ASP.NET Core Data Protection integration,
        /// that provides additional protection against token leakage.
        /// </summary>
        public bool UseReferenceAccessTokens { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether reference refresh tokens should be used.
        /// When set to <c>true</c>, the token payload is stored in the database and a
        /// crypto-secure random identifier is returned to the client application.
        /// Enabling this option is useful when storing a very large number of claims
        /// in the tokens, but it is RECOMMENDED to enable column encryption
        /// in the database or use the ASP.NET Core Data Protection integration,
        /// that provides additional protection against token leakage.
        /// </summary>
        public bool UseReferenceRefreshTokens { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether rolling tokens should be used.
        /// When disabled, no new token is issued and the refresh token lifetime is
        /// dynamically managed by updating the token entry in the database.
        /// When this option is enabled, a new refresh token is issued for each
        /// refresh token request (and the previous one is automatically revoked
        /// unless token storage was explicitly disabled in the options).
        /// </summary>
        public bool UseRollingRefreshTokens { get; set; }
    }
}
