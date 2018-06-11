/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Linq;
using System.Text;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration
    /// used by OpenIddict is in a consistent and valid state.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictServerInitializer : IPostConfigureOptions<OpenIddictServerOptions>
    {
        private readonly IDistributedCache _cache;
        private readonly IDataProtectionProvider _dataProtectionProvider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictServerInitializer"/> class.
        /// </summary>
        public OpenIddictServerInitializer(
            [NotNull] IDistributedCache cache,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
        {
            _cache = cache;
            _dataProtectionProvider = dataProtectionProvider;
        }

        /// <summary>
        /// Populates the default OpenID Connect server options and ensure
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([NotNull] string name, [NotNull] OpenIddictServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            if (options.RandomNumberGenerator == null)
            {
                throw new InvalidOperationException("A random number generator must be registered.");
            }

            if (options.ApplicationProviderType != null)
            {
                if (options.ApplicationProvider != null)
                {
                    throw new InvalidOperationException("An application provider cannot be registered when a type is specified.");
                }

                if (!typeof(OpenIdConnectServerProvider).IsAssignableFrom(options.ApplicationProviderType))
                {
                    throw new InvalidOperationException("Application providers must inherit from OpenIdConnectServerProvider.");
                }
            }

            // When no distributed cache has been registered in the options,
            // try to resolve it from the dependency injection container.
            if (options.Cache == null)
            {
                options.Cache = _cache;
            }

            // If OpenIddict was configured to use reference tokens, replace the default access tokens/
            // authorization codes/refresh tokens formats using a specific data protector to ensure
            // that encrypted tokens stored in the database cannot be treated as valid tokens if the
            // reference tokens option is later turned off by the developer.
            if (options.UseReferenceTokens)
            {
                // Note: a default data protection provider is always registered by
                // the OpenID Connect server handler when none is explicitly set but
                // this initializer is registered to be invoked before ASOS' initializer.
                // To ensure the provider property is never null, it's manually set here.
                if (options.DataProtectionProvider == null)
                {
                    options.DataProtectionProvider = _dataProtectionProvider;
                }

                if (options.AccessTokenFormat == null)
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        nameof(OpenIdConnectServerHandler),
                        nameof(options.AccessTokenFormat),
                        nameof(options.UseReferenceTokens), name);

                    options.AccessTokenFormat = new TicketDataFormat(protector);
                }

                if (options.AuthorizationCodeFormat == null)
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        nameof(OpenIdConnectServerHandler),
                        nameof(options.AuthorizationCodeFormat),
                        nameof(options.UseReferenceTokens), name);

                    options.AuthorizationCodeFormat = new TicketDataFormat(protector);
                }

                if (options.RefreshTokenFormat == null)
                {
                    var protector = options.DataProtectionProvider.CreateProtector(
                        nameof(OpenIdConnectServerHandler),
                        nameof(options.RefreshTokenFormat),
                        nameof(options.UseReferenceTokens), name);

                    options.RefreshTokenFormat = new TicketDataFormat(protector);
                }
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
                throw new InvalidOperationException("The authorization endpoint must be enabled to use the authorization code and implicit flows.");
            }

            // Ensure the token endpoint has been enabled when the authorization code,
            // client credentials, password or refresh token grants are supported.
            if (!options.TokenEndpointPath.HasValue && (options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode) ||
                                                        options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.ClientCredentials) ||
                                                        options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Password) ||
                                                        options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken)))
            {
                throw new InvalidOperationException(
                    "The token endpoint must be enabled to use the authorization code, client credentials, password and refresh token flows.");
            }

            if (options.RevocationEndpointPath.HasValue && options.DisableTokenStorage)
            {
                throw new InvalidOperationException("The revocation endpoint cannot be enabled when token storage is disabled.");
            }

            if (options.UseReferenceTokens && options.DisableTokenStorage)
            {
                throw new InvalidOperationException("Reference tokens cannot be used when disabling token storage.");
            }

            if (options.UseReferenceTokens && options.AccessTokenHandler != null)
            {
                throw new InvalidOperationException("Reference tokens cannot be used when configuring JWT as the access token format.");
            }

            if (options.UseSlidingExpiration && options.DisableTokenStorage && !options.UseRollingTokens)
            {
                throw new InvalidOperationException(
                    "Sliding expiration must be disabled when turning off token storage if rolling tokens are not used.");
            }

            if (options.AccessTokenHandler != null && options.SigningCredentials.Count == 0)
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("At least one signing key must be registered when using JWT as the access token format.")
                    .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                    .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                    .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                    .ToString());
            }

            // Ensure at least one asymmetric signing certificate/key was registered if the implicit flow was enabled.
            if (!options.SigningCredentials.Any(credentials => credentials.Key is AsymmetricSecurityKey) &&
                 options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.Implicit))
            {
                throw new InvalidOperationException(new StringBuilder()
                    .AppendLine("At least one asymmetric signing key must be registered when enabling the implicit flow.")
                    .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                    .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                    .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                    .ToString());
            }

            // Automatically add the offline_access scope if the refresh token grant has been enabled.
            if (options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken))
            {
                options.Scopes.Add(OpenIdConnectConstants.Scopes.OfflineAccess);
            }
        }
    }
}
