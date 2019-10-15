/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

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
        /// OpenIddict server services. Note: only symmetric credentials are supported.
        /// </summary>
        public IList<EncryptingCredentials> EncryptionCredentials { get; } = new List<EncryptingCredentials>();

        /// <summary>
        /// Gets the list of credentials used to sign the tokens issued by the OpenIddict server services.
        /// Both asymmetric and symmetric keys are supported, but only asymmetric keys can be used to sign identity tokens.
        /// Note that only asymmetric RSA and ECDSA keys can be exposed by the JWKS metadata endpoint.
        /// </summary>
        public IList<SigningCredentials> SigningCredentials { get; } = new List<SigningCredentials>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the authorization endpoint.
        /// </summary>
        public IList<Uri> AuthorizationEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the configuration endpoint.
        /// </summary>
        public IList<Uri> ConfigurationEndpointUris { get; } = new List<Uri>
        {
            new Uri("/.well-known/openid-configuration", UriKind.Relative),
            new Uri("/.well-known/oauth-authorization-server", UriKind.Relative)
        };

        /// <summary>
        /// Gets the absolute and relative URIs associated to the cryptography endpoint.
        /// </summary>
        public IList<Uri> CryptographyEndpointUris { get; } = new List<Uri>
        {
            new Uri("/.well-known/jwks", UriKind.Relative)
        };

        /// <summary>
        /// Gets the absolute and relative URIs associated to the introspection endpoint.
        /// </summary>
        public IList<Uri> IntrospectionEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the logout endpoint.
        /// </summary>
        public IList<Uri> LogoutEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the revocation endpoint.
        /// </summary>
        public IList<Uri> RevocationEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the token endpoint.
        /// </summary>
        public IList<Uri> TokenEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets the absolute and relative URIs associated to the userinfo endpoint.
        /// </summary>
        public IList<Uri> UserinfoEndpointUris { get; } = new List<Uri>();

        /// <summary>
        /// Gets or sets the JWT handler used to protect and unprotect tokens.
        /// </summary>
        public OpenIddictServerJsonWebTokenHandler JsonWebTokenHandler { get; set; } = new OpenIddictServerJsonWebTokenHandler
        {
            SetDefaultTimesOnTokenCreation = false
        };

        /// <summary>
        /// Gets the token validation parameters used by the OpenIddict server services.
        /// </summary>
        public TokenValidationParameters TokenValidationParameters { get; } = new TokenValidationParameters
        {
            ClockSkew = TimeSpan.Zero,
            NameClaimType = OpenIddictConstants.Claims.Name,
            RoleClaimType = OpenIddictConstants.Claims.Role,
            // Note: audience and lifetime are manually validated by OpenIddict itself.
            ValidateAudience = false,
            ValidateLifetime = false
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
        /// Gets or sets a boolean indicating whether the degraded mode is enabled. When this degraded mode
        /// is enabled, all the security checks that depend on the OpenIddict core managers are disabled.
        /// This option MUST be enabled with extreme caution and custom handlers MUST be registered to
        /// properly validate OpenID Connect requests.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public bool EnableDegradedMode { get; set; }

        /// <summary>
        /// Gets the list of the user-defined/custom handlers responsible of processing the OpenIddict server requests.
        /// Note: the handlers added to this list must be also registered in the DI container using an appropriate lifetime.
        /// </summary>
        public IList<OpenIddictServerHandlerDescriptor> CustomHandlers { get; } =
            new List<OpenIddictServerHandlerDescriptor>();

        /// <summary>
        /// Gets the list of the built-in handlers responsible of processing the OpenIddict server requests
        /// </summary>
        public IList<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
            new List<OpenIddictServerHandlerDescriptor>(OpenIddictServerHandlers.DefaultHandlers);

        /// <summary>
        /// Gets or sets a boolean indicating whether new refresh tokens should be issued during a refresh token request.
        /// Set this property to <c>true</c> to issue a new refresh token, <c>false</c> to prevent the OpenID Connect
        /// server middleware from issuing new refresh tokens when receiving a grant_type=refresh_token request.
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
        public ISet<string> Claims { get; } = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIddictConstants.Claims.Audience,
            OpenIddictConstants.Claims.ExpiresAt,
            OpenIddictConstants.Claims.IssuedAt,
            OpenIddictConstants.Claims.Issuer,
            OpenIddictConstants.Claims.JwtId,
            OpenIddictConstants.Claims.Subject
        };

        /// <summary>
        /// Gets or sets a boolean indicating whether authorization storage should be disabled.
        /// When disabled, ad-hoc authorizations are not created when an authorization code or
        /// refresh token is issued and can't be revoked to prevent associated tokens from being used.
        /// </summary>
        public bool DisableAuthorizationStorage { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether token storage should be disabled.
        /// When disabled, authorization code and refresh tokens are not stored
        /// and cannot be revoked. Using this option is generally not recommended.
        /// </summary>
        public bool DisableTokenStorage { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether scope validation is disabled.
        /// </summary>
        public bool DisableScopeValidation { get; set; }

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect flows enabled for this application.
        /// </summary>
        public ISet<string> GrantTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect response types enabled for this application.
        /// Response types are automatically inferred from the supported standard grant types,
        /// but additional values can be added for advanced scenarios (e.g custom type support).
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public ISet<string> ResponseTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets the OAuth 2.0/OpenID Connect response modes enabled for this application.
        /// Response modes are automatically inferred from the supported standard grant types,
        /// but additional values can be added for advanced scenarios (e.g custom mode support).
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public ISet<string> ResponseModes { get; } = new HashSet<string>(StringComparer.Ordinal);

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
        public ISet<string> Scopes { get; } = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIddictConstants.Scopes.OpenId
        };

        /// <summary>
        /// Gets or sets a boolean indicating whether reference tokens should be used.
        /// When set to <c>true</c>, authorization codes, access tokens and refresh tokens
        /// are stored as ciphertext in the database and a crypto-secure random identifier
        /// is returned to the client application. Enabling this option is useful
        /// to keep track of all the issued tokens, when storing a very large number
        /// of claims in the authorization codes, access tokens and refresh tokens
        /// or when immediate revocation of reference access tokens is desired.
        /// Note: this option cannot be used when configuring JWT as the access token format.
        /// </summary>
        public bool UseReferenceTokens { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether rolling tokens should be used.
        /// When disabled, no new token is issued and the refresh token lifetime is
        /// dynamically managed by updating the token entry in the database.
        /// When this option is enabled, a new refresh token is issued for each
        /// refresh token request (and the previous one is automatically revoked
        /// unless token revocation was explicitly disabled in the options).
        /// </summary>
        public bool UseRollingTokens { get; set; }
    }
}
