/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Extensions;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict;

namespace Microsoft.AspNetCore.Builder {
    /// <summary>
    /// Exposes the necessary methods required to configure OpenIddict.
    /// </summary>
    public class OpenIddictBuilder {
        /// <summary>
        /// Initializes a new instance of <see cref="OpenIddictBuilder"/>.
        /// </summary>
        /// <param name="services">The services collection.</param>
        public OpenIddictBuilder(IServiceCollection services) {
            Services = services;
        }

        /// <summary>
        /// Gets or sets the type corresponding to the Application entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type ApplicationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Authorization entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type AuthorizationType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Scope entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type ScopeType { get; set; }

        /// <summary>
        /// Gets or sets the type corresponding to the Token entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type TokenType { get; set; }

        /// <summary>
        /// Gets the services collection.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public IServiceCollection Services { get; }

        /// <summary>
        /// Amends the default OpenIddict configuration.
        /// </summary>
        /// <param name="configuration">The delegate used to configure the OpenIddict options.</param>
        /// <remarks>This extension can be safely called multiple times.</remarks>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder Configure([NotNull] Action<OpenIddictOptions> configuration) {
            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            Services.Configure(configuration);

            return this;
        }

        /// <summary>
        /// Adds a custom application manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddApplicationManager<TManager>() where TManager : class
            => AddApplicationManager(typeof(TManager));

        /// <summary>
        /// Adds a custom application manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddApplicationManager([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictApplicationManager<>).MakeGenericType(ApplicationType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictApplicationManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom application store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddApplicationStore<TStore>() where TStore : class
            => AddApplicationStore(typeof(TStore));

        /// <summary>
        /// Adds a custom application store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddApplicationStore([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictApplicationStore<>).MakeGenericType(ApplicationType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictApplicationStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom authorization manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddAuthorizationManager<TManager>() where TManager : class
            => AddAuthorizationManager(typeof(TManager));

        /// <summary>
        /// Adds a custom authorization manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddAuthorizationManager([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictAuthorizationManager<>).MakeGenericType(AuthorizationType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictAuthorizationManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom authorization store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddAuthorizationStore<TStore>() where TStore : class
            => AddAuthorizationStore(typeof(TStore));

        /// <summary>
        /// Adds a custom authorization store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddAuthorizationStore([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictAuthorizationStore<>).MakeGenericType(AuthorizationType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictAuthorizationStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom scope manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddScopeManager<TManager>() where TManager : class
            => AddScopeManager(typeof(TManager));

        /// <summary>
        /// Adds a custom scope manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddScopeManager([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictScopeManager<>).MakeGenericType(ScopeType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictScopeManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom scope store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddScopeStore<TStore>() where TStore : class
            => AddScopeStore(typeof(TStore));

        /// <summary>
        /// Adds a custom scope store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddScopeStore([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictScopeStore<>).MakeGenericType(ScopeType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictScopeStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom token manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddTokenManager<TManager>() where TManager : class
            => AddTokenManager(typeof(TManager));

        /// <summary>
        /// Adds a custom token manager.
        /// </summary>
        /// <param name="type">The type of the custom manager.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddTokenManager([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(OpenIddictTokenManager<>).MakeGenericType(TokenType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictTokenManager.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Adds a custom token store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public OpenIddictBuilder AddTokenStore<TStore>() where TStore : class
            => AddTokenStore(typeof(TStore));

        /// <summary>
        /// Adds a custom token store.
        /// </summary>
        /// <param name="type">The type of the custom store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddTokenStore([NotNull] Type type) {
            if (type == null) {
                throw new ArgumentNullException(nameof(type));
            }

            var contract = typeof(IOpenIddictTokenStore<>).MakeGenericType(TokenType);
            if (!contract.IsAssignableFrom(type)) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictTokenStore.");
            }

            Services.AddScoped(contract, type);

            return this;
        }

        /// <summary>
        /// Registers a new ephemeral key used to sign the tokens issued by OpenIddict: the key
        /// is discarded when the application shuts down and tokens signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddEphemeralSigningKey() {
            return Configure(options => options.SigningCredentials.AddEphemeralKey());
        }

        /// <summary>
        /// Registers a new ephemeral key used to sign the tokens issued by OpenIddict: the key
        /// is discarded when the application shuts down and tokens signed using this key are
        /// automatically invalidated. This method should only be used during development.
        /// On production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <param name="algorithm">The algorithm associated with the signing key.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddEphemeralSigningKey([NotNull] string algorithm) {
            if (string.IsNullOrEmpty(algorithm)) {
                throw new ArgumentException("The algorithm cannot be null or empty.", nameof(algorithm));
            }

            return Configure(options => options.SigningCredentials.AddEphemeralKey(algorithm));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> that is used to sign the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="certificate">The certificate used to sign the security tokens issued by the server.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddSigningCertificate([NotNull] X509Certificate2 certificate) {
            if (certificate == null) {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (!certificate.HasPrivateKey) {
                throw new InvalidOperationException("The certificate doesn't contain the required private key.");
            }

            return Configure(options => options.SigningCredentials.AddCertificate(certificate));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from an
        /// embedded resource and used to sign the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="assembly">The assembly containing the certificate.</param>
        /// <param name="resource">The name of the embedded resource.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddSigningCertificate(
            [NotNull] Assembly assembly, [NotNull] string resource, [NotNull] string password) {
            if (assembly == null) {
                throw new ArgumentNullException(nameof(assembly));
            }

            if (string.IsNullOrEmpty(resource)) {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException(nameof(password));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(assembly, resource, password));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> extracted from a
        /// stream and used to sign the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddSigningCertificate([NotNull] Stream stream, [NotNull] string password) {
            if (stream == null) {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException(nameof(password));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(stream, password));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> extracted from a
        /// stream and used to sign the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="stream">The stream containing the certificate.</param>
        /// <param name="password">The password used to open the certificate.</param>
        /// <param name="flags">
        /// An enumeration of flags indicating how and where
        /// to store the private key of the certificate.
        /// </param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddSigningCertificate(
            [NotNull] Stream stream, [NotNull] string password, X509KeyStorageFlags flags) {
            if (stream == null) {
                throw new ArgumentNullException(nameof(stream));
            }

            if (string.IsNullOrEmpty(password)) {
                throw new ArgumentNullException(nameof(password));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(stream, password, flags));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from the X.509
        /// machine store and used to sign the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddSigningCertificate([NotNull] string thumbprint) {
            if (string.IsNullOrEmpty(thumbprint)) {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(thumbprint));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> retrieved from the given
        /// X.509 store and used to sign the tokens issued by OpenIddict.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate used to identify it in the X.509 store.</param>
        /// <param name="name">The name of the X.509 store.</param>
        /// <param name="location">The location of the X.509 store.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddSigningCertificate(
            [NotNull] string thumbprint, StoreName name, StoreLocation location) {
            if (string.IsNullOrEmpty(thumbprint)) {
                throw new ArgumentNullException(nameof(thumbprint));
            }

            return Configure(options => options.SigningCredentials.AddCertificate(thumbprint, name, location));
        }

        /// <summary>
        /// Registers a <see cref="SecurityKey"/> used to sign the tokens issued by OpenIddict.
        /// Note: using <see cref="RsaSecurityKey"/> asymmetric keys is recommended on production.
        /// </summary>
        /// <param name="key">The security key.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddSigningKey([NotNull] SecurityKey key) {
            if (key == null) {
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
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AllowAuthorizationCodeFlow() {
            return Configure(options => options.GrantTypes.Add(
                OpenIdConnectConstants.GrantTypes.AuthorizationCode));
        }

        /// <summary>
        /// Enables client credentials flow support. For more information about this
        /// specific OAuth2 flow, visit https://tools.ietf.org/html/rfc6749#section-4.4.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AllowClientCredentialsFlow() {
            return Configure(options => options.GrantTypes.Add(
                OpenIdConnectConstants.GrantTypes.ClientCredentials));
        }

        /// <summary>
        /// Enables custom grant type support.
        /// </summary>
        /// <param name="type">The grant type associated with the flow.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AllowCustomFlow([NotNull] string type) {
            if (string.IsNullOrEmpty(type)) {
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
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AllowImplicitFlow() {
            return Configure(options => options.GrantTypes.Add(
                OpenIdConnectConstants.GrantTypes.Implicit));
        }

        /// <summary>
        /// Enables password flow support. For more information about this specific
        /// OAuth2 flow, visit https://tools.ietf.org/html/rfc6749#section-4.3.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AllowPasswordFlow() {
            return Configure(options => options.GrantTypes.Add(
                OpenIdConnectConstants.GrantTypes.Password));
        }

        /// <summary>
        /// Enables refresh token flow support. For more information about this
        /// specific OAuth2 flow, visit https://tools.ietf.org/html/rfc6749#section-6.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AllowRefreshTokenFlow() {
            return Configure(options => options.GrantTypes.Add(
                OpenIdConnectConstants.GrantTypes.RefreshToken));
        }

        /// <summary>
        /// Disables the configuration endpoint.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder DisableConfigurationEndpoint() {
            return Configure(options => options.ConfigurationEndpointPath = PathString.Empty);
        }

        /// <summary>
        /// Disables the cryptography endpoint.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder DisableCryptographyEndpoint() {
            return Configure(options => options.CryptographyEndpointPath = PathString.Empty);
        }

        /// <summary>
        /// Disables the HTTPS requirement during development.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder DisableHttpsRequirement() {
            return Configure(options => options.AllowInsecureHttp = true);
        }

        /// <summary>
        /// Disables sliding expiration, which prevents OpenIddict from issuing a new
        /// refresh token when receiving a grant_type=refresh_token token request.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder DisableSlidingExpiration() {
            return Configure(options => options.UseSlidingExpiration = false);
        }

        /// <summary>
        /// Enables the authorization endpoint.
        /// </summary>
        /// <param name="path">The relative path of the authorization endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableAuthorizationEndpoint(PathString path) {
            if (!path.HasValue) {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.AuthorizationEndpointPath = path);
        }

        /// <summary>
        /// Enables the introspection endpoint.
        /// </summary>
        /// <param name="path">The relative path of the logout endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableIntrospectionEndpoint(PathString path) {
            if (!path.HasValue) {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.IntrospectionEndpointPath = path);
        }

        /// <summary>
        /// Enables the logout endpoint.
        /// </summary>
        /// <param name="path">The relative path of the logout endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableLogoutEndpoint(PathString path) {
            if (!path.HasValue) {
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
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableRequestCaching() {
            return Configure(options => options.EnableRequestCaching = true);
        }

        /// <summary>
        /// Enables the revocation endpoint.
        /// </summary>
        /// <param name="path">The relative path of the revocation endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableRevocationEndpoint(PathString path) {
            if (!path.HasValue) {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.RevocationEndpointPath = path);
        }

        /// <summary>
        /// Enables the token endpoint.
        /// </summary>
        /// <param name="path">The relative path of the token endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableTokenEndpoint(PathString path) {
            if (!path.HasValue) {
                throw new ArgumentException("The path cannot be empty.", nameof(path));
            }

            return Configure(options => options.TokenEndpointPath = path);
        }

        /// <summary>
        /// Enables the userinfo endpoint.
        /// </summary>
        /// <param name="path">The relative path of the userinfo endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableUserinfoEndpoint(PathString path) {
            if (!path.HasValue) {
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
        public virtual OpenIddictBuilder RequireClientIdentification() {
            return Configure(options => options.RequireClientIdentification = true);
        }

        /// <summary>
        /// Sets the access token lifetime, after which client applications must retrieve
        /// a new access token by making a grant_type=refresh_token token request
        /// or a prompt=none authorization request, depending on the selected flow.
        /// Using long-lived access tokens or tokens that never expire is not recommended.
        /// </summary>
        /// <param name="lifetime">The access token lifetime.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder SetAccessTokenLifetime(TimeSpan lifetime) {
            return Configure(options => options.AccessTokenLifetime = lifetime);
        }

        /// <summary>
        /// Sets the authorization code lifetime, after which client applications
        /// are unable to send a grant_type=authorization_code token request.
        /// Using short-lived authorization codes is strongly recommended.
        /// </summary>
        /// <param name="lifetime">The authorization code lifetime.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder SetAuthorizationCodeLifetime(TimeSpan lifetime) {
            return Configure(options => options.AuthorizationCodeLifetime = lifetime);
        }

        /// <summary>
        /// Sets the identity token lifetime, after which client
        /// applications should refuse processing identity tokens.
        /// </summary>
        /// <param name="lifetime">The identity token lifetime.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder SetIdentityTokenLifetime(TimeSpan lifetime) {
            return Configure(options => options.IdentityTokenLifetime = lifetime);
        }

        /// <summary>
        /// Sets the refresh token lifetime, after which client applications must get
        /// a new authorization from the user. When sliding expiration is enabled,
        /// a new refresh token is always issued to the client application,
        /// which prolongs the validity period of the refresh token.
        /// </summary>
        /// <param name="lifetime">The refresh token lifetime.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder SetRefreshTokenLifetime(TimeSpan lifetime) {
            return Configure(options => options.RefreshTokenLifetime = lifetime);
        }

        /// <summary>
        /// Configures OpenIddict to use a specific data protection provider
        /// instead of relying on the default instance provided by the DI container.
        /// </summary>
        /// <param name="provider">The data protection provider used to create token protectors.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder UseDataProtectionProvider(IDataProtectionProvider provider) {
            if (provider == null) {
                throw new ArgumentNullException(nameof(provider));
            }

            return Configure(options => options.DataProtectionProvider = provider);
        }

        /// <summary>
        /// Sets JWT as the default token format for access tokens.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder UseJsonWebTokens() {
            return Configure(options => options.AccessTokenHandler = new JwtSecurityTokenHandler());
        }
    }
}