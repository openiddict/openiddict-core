/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.Extensions.Caching.Distributed;
using OpenIddict.Abstractions;

namespace OpenIddict.Server
{
    /// <summary>
    /// Provides various settings needed to configure the OpenIddict server handler.
    /// </summary>
    public class OpenIddictServerOptions : OpenIdConnectServerOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerOptions"/> class.
        /// </summary>
        public OpenIddictServerOptions()
        {
            Provider = null;
            ProviderType = typeof(OpenIddictServerProvider);
        }

        /// <summary>
        /// Gets or sets a boolean determining whether client identification is optional.
        /// Enabling this option allows client applications to communicate with the token
        /// and revocation endpoints without having to send their client identifier.
        /// </summary>
        public bool AcceptAnonymousClients { get; set; }

        /// <summary>
        /// Gets or sets the distributed cache used by OpenIddict. If no cache is explicitly
        /// provided, the cache registered in the dependency injection container is used.
        /// </summary>
        public IDistributedCache Cache { get; set; }

        /// <summary>
        /// Gets the OAuth2/OpenID Connect claims supported by this application.
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
        /// Gets or sets a boolean indicating whether request caching should be enabled.
        /// When enabled, both authorization and logout requests are automatically stored
        /// in the distributed cache, which allows flowing large payloads across requests.
        /// Enabling this option is recommended when using external authentication providers
        /// or when large GET or POST OpenID Connect authorization requests support is required.
        /// </summary>
        public bool EnableRequestCaching { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether scope validation is disabled.
        /// </summary>
        public bool DisableScopeValidation { get; set; }

        /// <summary>
        /// Gets the OAuth2/OpenID Connect flows enabled for this application.
        /// </summary>
        public ISet<string> GrantTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

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
        /// Gets or sets the random number generator used to generate crypto-secure identifiers.
        /// </summary>
        public RandomNumberGenerator RandomNumberGenerator { get; set; } = RandomNumberGenerator.Create();

        /// <summary>
        /// Gets or sets the caching policy used to determine how long the authorization
        /// and end session requests should be cached by the distributed cache implementation.
        /// </summary>
        public DistributedCacheEntryOptions RequestCachingPolicy { get; set; } = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1),
            SlidingExpiration = TimeSpan.FromMinutes(30)
        };

        /// <summary>
        /// Gets or sets a boolean indicating whether PKCE must be used by client applications
        /// when requesting an authorization code (e.g when using the code or hybrid flows).
        /// If this property is set to <c>true</c>, authorization requests that lack the
        /// code_challenge/code_challenge_method parameters will be automatically rejected.
        /// </summary>
        public bool RequireProofKeyForCodeExchange { get; set; }

        /// <summary>
        /// Gets the OAuth2/OpenID Connect scopes enabled for this application.
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
