/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes the necessary methods required to configure the OpenIddict server services.
    /// </summary>
    public class OpenIddictServerBuilder
    {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictServerBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictServerBuilder([NotNull] IServiceCollection services)
        {
            if (services == null)
            {
                throw new ArgumentNullException(nameof(services));
            }

            Services = services;
        }

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict server configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder Configure([NotNull] Action<OpenIddictServerOptions> configuration)
        {
            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(OpenIddictServerDefaults.AuthenticationScheme, configuration);

            return this;
        }

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development
        /// certificate used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddDevelopmentSigningCertificate()
            => Configure(options => options.SigningCredentials.AddDevelopmentCertificate());

        /// <summary>
        /// Registers (and generates if necessary) a user-specific development
        /// certificate used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <param name="subject">The subject name associated with the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddDevelopmentSigningCertificate([NotNull] X500DistinguishedName subject)
        {
            if (subject == null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            return Configure(options => options.SigningCredentials.AddDevelopmentCertificate(subject));
        }

        /// <summary>
        /// Registers a new ephemeral key used to sign the JWT tokens issued by OpenIddict: the key
        /// is discarded when the application shuts down and tokens signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEphemeralSigningKey()
            => Configure(options => options.SigningCredentials.AddEphemeralKey());

        /// <summary>
        /// Registers a new ephemeral key used to sign the JWT tokens issued by OpenIddict: the key
        /// is discarded when the application shuts down and tokens signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="algorithm">The algorithm associated with the signing key.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEphemeralSigningKey([NotNull] string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
            {
                throw new ArgumentException("The algorithm cannot be null or empty.", nameof(algorithm));
            }

            return Configure(options => options.SigningCredentials.AddEphemeralKey(algorithm));
        }

        /// <summary>
        /// Registers a <see cref="SecurityKey"/> used to encrypt the JWT access tokens issued by OpenIddict.
        /// </summary>
        /// <param name="key">The security key.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddEncryptingKey([NotNull] SecurityKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return Configure(options => options.EncryptingCredentials.AddKey(key));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> that is used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <param name="certificate">The certificate used to sign the security tokens issued by the server.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate([NotNull] X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (!certificate.HasPrivateKey)
            {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            return Configure(options => options.SigningCredentials.AddCertificate(certificate));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource and used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password)
        {
            if (assembly == null)
            {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(assembly, resource, password));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> extracted from a
        /// stream and used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate([NotNull] Stream stream, [NotNull] string password)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(stream, password));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> extracted from a
        /// stream and used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">
        /// An enumeration of flags indicating how and where
        /// to store the private key of the certificate.
        /// </param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(
            [NotNull] Stream stream, [NotNull] string password, X509KeyStorageFlags flags)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(stream, password, flags));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from the X.509
        /// machine store and used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate([NotNull] string thumbprint)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(thumbprint));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from the given
        /// X.509 store and used to sign the JWT tokens issued by OpenIddict.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningCertificate(
            [NotNull] string thumbprint, StoreName name, StoreLocation location)
        {
            if (string.IsNullOrEmpty(thumbprint))
            {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(thumbprint, name, location));
        }

        /// <summary>
        /// Registers a <see cref="SecurityKey"/> used to sign the JWT tokens issued by OpenIddict.
        /// Note: using <see cref="RsaSecurityKey"/> asymmetric keys is recommended on production.
        /// </summary>
        /// <param name="key">The security key.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AddSigningKey([NotNull] SecurityKey key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return Configure(options => options.SigningCredentials.AddKey(key));
        }

        /// <summary>
        /// Enables authorization code flow support. For more information
        /// about this specific OAuth2/OpenID Connect flow, visit
        /// https://tools.ietf.org/html/rfc6749#section-4.1 and
        /// http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowAuthorizationCodeFlow()
            => Configure(options => options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.AuthorizationCode));

        /// <summary>
        /// Enables client credentials flow support. For more information about this
        /// specific OAuth2 flow, visit https://tools.ietf.org/html/rfc6749#section-4.4.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowClientCredentialsFlow()
            => Configure(options => options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.ClientCredentials));

        /// <summary>
        /// Enables custom grant type support.
        /// </summary>
        /// <param name="type">The grant type associated with the flow.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowCustomFlow([NotNull] string type)
        {
            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException("The grant type cannot be null or empty.", nameof(type));
            }

            return Configure(options => options.GrantTypes.Add(type));
        }

        /// <summary>
        /// Enables implicit flow support. For more information
        /// about this specific OAuth2/OpenID Connect flow, visit
        /// https://tools.ietf.org/html/rfc6749#section-4.2 and
        /// http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowImplicitFlow()
            => Configure(options => options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Implicit));

        /// <summary>
        /// Enables password flow support. For more information about this specific
        /// OAuth2 flow, visit https://tools.ietf.org/html/rfc6749#section-4.3.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowPasswordFlow()
            => Configure(options => options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Password));

        /// <summary>
        /// Enables refresh token flow support. For more information about this
        /// specific OAuth2 flow, visit https://tools.ietf.org/html/rfc6749#section-6.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder AllowRefreshTokenFlow()
            => Configure(options => options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.RefreshToken));

        /// <summary>
        /// Disables the configuration endpoint.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableConfigurationEndpoint()
            => Configure(options => options.ConfigurationEndpointPath = PathString.Empty);

        /// <summary>
        /// Disables the cryptography endpoint.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableCryptographyEndpoint()
            => Configure(options => options.CryptographyEndpointPath = PathString.Empty);

        /// <summary>
        /// Disables the HTTPS requirement during development.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableHttpsRequirement()
            => Configure(options => options.AllowInsecureHttp = true);

        /// <summary>
        /// Disables sliding expiration. When using this option, refresh tokens
        /// are issued with a fixed expiration date: when it expires, a complete
        /// authorization flow must be started to retrieve a new refresh token.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableSlidingExpiration()
            => Configure(options => options.UseSlidingExpiration = false);

        /// <summary>
        /// Disables token revocation, so that authorization code and
        /// refresh tokens are never stored and cannot be revoked.
        /// Using this option is generally not recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder DisableTokenRevocation()
            => Configure(options => options.DisableTokenRevocation = true);

        /// <summary>
        /// Enables the authorization endpoint.
        /// </summary>
        /// <param name="path">The relative path of the authorization endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableAuthorizationEndpoint(PathString path)
        {
            if (!path.HasValue)
            {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.AuthorizationEndpointPath = path);
        }

        /// <summary>
        /// Enables the introspection endpoint.
        /// </summary>
        /// <param name="path">The relative path of the logout endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableIntrospectionEndpoint(PathString path)
        {
            if (!path.HasValue)
            {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.IntrospectionEndpointPath = path);
        }

        /// <summary>
        /// Enables the logout endpoint.
        /// </summary>
        /// <param name="path">The relative path of the logout endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableLogoutEndpoint(PathString path)
        {
            if (!path.HasValue)
            {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.LogoutEndpointPath = path);
        }

        /// <summary>
        /// Enables request caching, so that both authorization and logout requests
        /// are automatically stored in the distributed cache, which allows flowing
        /// large payloads across requests. Enabling this option is recommended
        /// when using external authentication providers or when large GET or POST
        /// OpenID Connect authorization requests support is required.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableRequestCaching()
            => Configure(options => options.EnableRequestCaching = true);

        /// <summary>
        /// Enables the revocation endpoint.
        /// </summary>
        /// <param name="path">The relative path of the revocation endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableRevocationEndpoint( PathString path)
        {
            if (!path.HasValue)
            {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.RevocationEndpointPath = path);
        }

        /// <summary>
        /// Rejects authorization and token requests that specify scopes that have not been
        /// registered using <see cref="RegisterScopes(string[])"/> or the scope manager.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableScopeValidation()
            => Configure(options => options.EnableScopeValidation = true);

        /// <summary>
        /// Enables the token endpoint.
        /// </summary>
        /// <param name="path">The relative path of the token endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableTokenEndpoint(PathString path)
        {
            if (!path.HasValue)
            {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.TokenEndpointPath = path);
        }

        /// <summary>
        /// Enables the userinfo endpoint.
        /// </summary>
        /// <param name="path">The relative path of the userinfo endpoint.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder EnableUserinfoEndpoint(PathString path)
        {
            if (!path.HasValue)
            {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.UserinfoEndpointPath = path);
        }

        /// <summary>
        /// Makes client identification mandatory so that token and revocation
        /// requests that don't specify a client_id are automatically rejected.
        /// Note: enabling this option doesn't prevent public clients from using
        /// the token and revocation endpoints, but specifying a client_id is required.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder RequireClientIdentification()
            => Configure(options => options.RequireClientIdentification = true);

        /// <summary>
        /// Sets the access token lifetime, after which client applications must retrieve
        /// a new access token by making a grant_type=refresh_token token request
        /// or a prompt=none authorization request, depending on the selected flow.
        /// Using long-lived access tokens or tokens that never expire is not recommended.
        /// </summary>
        /// <param name="lifetime">The access token lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetAccessTokenLifetime(TimeSpan lifetime)
            => Configure(options => options.AccessTokenLifetime = lifetime);

        /// <summary>
        /// Sets the authorization code lifetime, after which client applications
        /// are unable to send a grant_type=authorization_code token request.
        /// Using short-lived authorization codes is strongly recommended.
        /// </summary>
        /// <param name="lifetime">The authorization code lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetAuthorizationCodeLifetime(TimeSpan lifetime)
            => Configure(options => options.AuthorizationCodeLifetime = lifetime);

        /// <summary>
        /// Sets the identity token lifetime, after which client
        /// applications should refuse processing identity tokens.
        /// </summary>
        /// <param name="lifetime">The identity token lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetIdentityTokenLifetime(TimeSpan lifetime)
            => Configure(options => options.IdentityTokenLifetime = lifetime);

        /// <summary>
        /// Sets the refresh token lifetime, after which client applications must get
        /// a new authorization from the user. When sliding expiration is enabled,
        /// a new refresh token is always issued to the client application,
        /// which prolongs the validity period of the refresh token.
        /// </summary>
        /// <param name="lifetime">The refresh token lifetime.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetRefreshTokenLifetime(TimeSpan lifetime)
            => Configure(options => options.RefreshTokenLifetime = lifetime);

        /// <summary>
        /// Sets the issuer address, which is used as the base address
        /// for the endpoint URIs returned from the discovery endpoint.
        /// </summary>
        /// <param name="address">The issuer address.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder SetIssuer([NotNull] Uri address)
        {
            if (address == null)
            {
                throw new ArgumentNullException(nameof(address));
            }

            return Configure(options => options.Issuer = address);
        }

        /// <summary>
        /// Registers the specified claims as supported claims so
        /// they can be returned as part of the discovery document.
        /// </summary>
        /// <param name="claims">The supported claims.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder RegisterClaims([NotNull] params string[] claims)
        {
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            if (claims.Any(claim => string.IsNullOrEmpty(claim)))
            {
                throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));
            }

            return Configure(options => options.Claims.UnionWith(claims));
        }

        /// <summary>
        /// Registers the specified scopes as supported scopes so
        /// they can be returned as part of the discovery document.
        /// </summary>
        /// <param name="scopes">The supported scopes.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder RegisterScopes([NotNull] params string[] scopes)
        {
            if (scopes == null)
            {
                throw new ArgumentNullException(nameof(scopes));
            }

            if (scopes.Any(scope => string.IsNullOrEmpty(scope)))
            {
                throw new ArgumentException("Scopes cannot be null or empty.", nameof(scopes));
            }

            return Configure(options => options.Scopes.UnionWith(scopes));
        }

        /// <summary>
        /// Configures OpenIddict to use a specific data protection provider
        /// instead of relying on the default instance provided by the DI container.
        /// </summary>
        /// <param name="provider">The data protection provider used to create token protectors.</param>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder UseDataProtectionProvider([NotNull] IDataProtectionProvider provider)
        {
            if (provider == null)
            {
                throw new ArgumentNullException(nameof(provider));
            }

            return Configure(options => options.DataProtectionProvider = provider);
        }

        /// <summary>
        /// Sets JWT as the default token format for access tokens.
        /// Note: this option cannot be used when using reference tokens.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder UseJsonWebTokens()
            => Configure(options => options.AccessTokenHandler = new JwtSecurityTokenHandler
            {
                InboundClaimTypeMap = new Dictionary<string, string>(),
                OutboundClaimTypeMap = new Dictionary<string, string>()
            });

        /// <summary>
        /// Configures OpenIddict to use reference tokens, so that authorization codes,
        /// access tokens and refresh tokens are stored as ciphertext in the database
        /// (only an identifier is returned to the client application). Enabling this option
        /// is useful to keep track of all the issued tokens, when storing a very large
        /// number of claims in the authorization codes, access tokens and refresh tokens
        /// or when immediate revocation of reference access tokens is desired.
        /// Note: this option cannot be used when configuring JWT as the access token format.
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder UseReferenceTokens()
            => Configure(options => options.UseReferenceTokens = true);

        /// <summary>
        /// Configures OpenIddict to use rolling refresh tokens. When this option is enabled,
        /// a new refresh token is always issued for each refresh token request (and the previous
        /// one is automatically revoked unless token revocation was explicitly disabled).
        /// </summary>
        /// <returns>The <see cref="OpenIddictServerBuilder"/>.</returns>
        public OpenIddictServerBuilder UseRollingTokens()
            => Configure(options => options.UseRollingTokens = true);
    }
}