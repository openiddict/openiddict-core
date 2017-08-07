/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Linq;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration
    /// used by OpenIddict is in a consistent and valid state.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictInitializer : IPostConfigureOptions<OpenIddictOptions>
    {
        private readonly IDistributedCache _cache;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictInitializer"/> class.
        /// </summary>
        public OpenIddictInitializer([NotNull] IDistributedCache cache)
        {
            _cache = cache;
        }

        /// <summary>
        /// Populates the default OpenID Connect server options and ensure
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([NotNull] string name, [NotNull] OpenIddictOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            // When no distributed cache has been registered in the options,
            // try to resolve it from the dependency injection container.
            if (options.Cache == null)
            {
                options.Cache = _cache;
            }

            // Ensure at least one flow has been enabled.
            if (options.GrantTypes.Count == 0)
            {
                throw new InvalidOperationException("At least one OAuth2/OpenID Connect flow must be enabled.");
            }

            // Ensure the authorization endpoint has been enabled when
            // the authorization code or implicit grants are supported.
            if (!options.AuthorizationEndpointPath.HasValue && (options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode) ||
                                                                options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Implicit)))
            {
                throw new InvalidOperationException("The authorization endpoint must be enabled to use " +
                                                    "the authorization code and implicit flows.");
            }

            // Ensure the token endpoint has been enabled when the authorization code,
            // client credentials, password or refresh token grants are supported.
            if (!options.TokenEndpointPath.HasValue && (options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode) ||
                                                        options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.ClientCredentials) ||
                                                        options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Password) ||
                                                        options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken)))
            {
                throw new InvalidOperationException("The token endpoint must be enabled to use the authorization code, " +
                                                    "client credentials, password and refresh token flows.");
            }

            if (options.RevocationEndpointPath.HasValue && options.DisableTokenRevocation)
            {
                throw new InvalidOperationException("The revocation endpoint cannot be enabled when token revocation is disabled.");
            }

            if (options.AccessTokenHandler != null && options.SigningCredentials.Count == 0)
            {
                throw new InvalidOperationException(
                    "At least one signing key must be registered when using JWT as the access token format. " +
                    "Consider registering a X.509 certificate using 'services.AddOpenIddict().AddSigningCertificate()' " +
                    "or 'services.AddOpenIddict().AddDevelopmentSigningCertificate()' or call " +
                    "'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.");
            }

            // Ensure at least one asymmetric signing certificate/key was registered if the implicit flow was enabled.
            if (!options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey) &&
                 options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Implicit))
            {
                throw new InvalidOperationException(
                    "At least one asymmetric signing key must be registered when enabling the implicit flow. " +
                    "Consider registering a X.509 certificate using 'services.AddOpenIddict().AddSigningCertificate()' " +
                    "or 'services.AddOpenIddict().AddDevelopmentSigningCertificate()' or call " +
                    "'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.");
            }
        }
    }
}
