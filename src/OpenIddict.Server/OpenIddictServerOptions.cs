/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.Extensions.Caching.Distributed;

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
        /// Gets or sets the distributed cache used by OpenIddict. If no cache is explicitly
        /// provided, the cache registered in the dependency injection container is used.
        /// </summary>
        public IDistributedCache Cache { get; set; }

        /// <summary>
        /// Gets the OAuth2/OpenID Connect claims supported by this application.
        /// </summary>
        public ISet<string> Claims { get; } = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIdConnectConstants.Claims.Audience,
            OpenIdConnectConstants.Claims.ExpiresAt,
            OpenIdConnectConstants.Claims.IssuedAt,
            OpenIdConnectConstants.Claims.Issuer,
            OpenIdConnectConstants.Claims.Subject
        };

        /// <summary>
        /// Gets or sets a boolean indicating whether scope validation is enabled.
        /// </summary>
        public bool EnableScopeValidation { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether token revocation should be disabled.
        /// When disabled, authorization code and refresh tokens are not stored
        /// and cannot be revoked. Using this option is generally not recommended.
        /// </summary>
        public bool DisableTokenRevocation { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether request caching should be enabled.
        /// When enabled, both authorization and logout requests are automatically stored
        /// in the distributed cache, which allows flowing large payloads across requests.
        /// Enabling this option is recommended when using external authentication providers
        /// or when large GET or POST OpenID Connect authorization requests support is required.
        /// </summary>
        public bool EnableRequestCaching { get; set; }

        /// <summary>
        /// Gets the OAuth2/OpenID Connect flows enabled for this application.
        /// </summary>
        public ISet<string> GrantTypes { get; } = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the random number generator used to generate crypto-secure identifiers.
        /// </summary>
        public RandomNumberGenerator RandomNumberGenerator { get; set; } = RandomNumberGenerator.Create();

        /// <summary>
        /// Gets or sets a boolean determining whether client identification is required.
        /// Enabling this option requires registering a client application and sending a
        /// valid client_id when communicating with the token and revocation endpoints.
        /// </summary>
        public bool RequireClientIdentification { get; set; }

        /// <summary>
        /// Gets the OAuth2/OpenID Connect scopes enabled for this application.
        /// </summary>
        public ISet<string> Scopes { get; } = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIdConnectConstants.Scopes.OpenId
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
