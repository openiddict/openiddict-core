/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AspNet.Security.OpenIdConnect.Extensions;
using JetBrains.Annotations;
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
        /// Gets or sets the type corresponding to the Role entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type RoleType { get; set; }

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
        /// Gets or sets the type corresponding to the User entity.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public Type UserType { get; set; }

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
        public virtual OpenIddictBuilder AddApplicationManager<TManager>() {
            var contract = typeof(OpenIddictApplicationManager<>).MakeGenericType(ApplicationType);
            if (!contract.IsAssignableFrom(typeof(TManager))) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictApplicationManager.");
            }

            Services.AddScoped(contract, typeof(TManager));

            return this;
        }

        /// <summary>
        /// Adds a custom application store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddApplicationStore<TStore>() {
            var contract = typeof(IOpenIddictApplicationStore<>).MakeGenericType(ApplicationType);
            if (!contract.IsAssignableFrom(typeof(TStore))) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictApplicationStore.");
            }

            Services.AddScoped(contract, typeof(TStore));

            return this;
        }

        /// <summary>
        /// Adds a custom authorization manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddAuthorizationManager<TManager>() {
            var contract = typeof(OpenIddictAuthorizationManager<>).MakeGenericType(AuthorizationType);
            if (!contract.IsAssignableFrom(typeof(TManager))) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictAuthorizationManager.");
            }

            Services.AddScoped(contract, typeof(TManager));

            return this;
        }

        /// <summary>
        /// Adds a custom authorization store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddAuthorizationStore<TStore>() {
            var contract = typeof(IOpenIddictAuthorizationStore<>).MakeGenericType(AuthorizationType);
            if (!contract.IsAssignableFrom(typeof(TStore))) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictAuthorizationStore.");
            }

            Services.AddScoped(contract, typeof(TStore));

            return this;
        }

        /// <summary>
        /// Adds a custom scope manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddScopeManager<TManager>() {
            var contract = typeof(OpenIddictScopeManager<>).MakeGenericType(ScopeType);
            if (!contract.IsAssignableFrom(typeof(TManager))) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictScopeManager.");
            }

            Services.AddScoped(contract, typeof(TManager));

            return this;
        }

        /// <summary>
        /// Adds a custom scope store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddScopeStore<TStore>() {
            var contract = typeof(IOpenIddictScopeStore<>).MakeGenericType(ScopeType);
            if (!contract.IsAssignableFrom(typeof(TStore))) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictScopeStore.");
            }

            Services.AddScoped(contract, typeof(TStore));

            return this;
        }

        /// <summary>
        /// Adds a custom token manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddTokenManager<TManager>() {
            var contract = typeof(OpenIddictTokenManager<>).MakeGenericType(TokenType);
            if (!contract.IsAssignableFrom(typeof(TManager))) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictTokenManager.");
            }

            Services.AddScoped(contract, typeof(TManager));

            return this;
        }

        /// <summary>
        /// Adds a custom token store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddTokenStore<TStore>() {
            var contract = typeof(IOpenIddictTokenStore<>).MakeGenericType(TokenType);
            if (!contract.IsAssignableFrom(typeof(TStore))) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictTokenStore.");
            }

            Services.AddScoped(contract, typeof(TStore));

            return this;
        }

        /// <summary>
        /// Adds a custom user manager.
        /// </summary>
        /// <typeparam name="TManager">The type of the custom manager.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddUserManager<TManager>() {
            var contract = typeof(OpenIddictUserManager<>).MakeGenericType(UserType);
            if (!contract.IsAssignableFrom(typeof(TManager))) {
                throw new InvalidOperationException("Custom managers must be derived from OpenIddictUserManager.");
            }

            Services.AddScoped(contract, typeof(TManager));

            return this;
        }

        /// <summary>
        /// Adds a custom user store.
        /// </summary>
        /// <typeparam name="TStore">The type of the custom store.</typeparam>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddUserStore<TStore>() {
            var contract = typeof(IOpenIddictTokenStore<>).MakeGenericType(UserType);
            if (!contract.IsAssignableFrom(typeof(TStore))) {
                throw new InvalidOperationException("Custom stores must implement IOpenIddictUserStore.");
            }

            Services.AddScoped(contract, typeof(TStore));

            return this;
        }

        /// <summary>
        /// Registers a new OpenIddict module. If a module with the same name already
        /// exists, the new instance is ignored and this extension has no effect.
        /// </summary>
        /// <param name="name">The name of the OpenIddict module.</param>
        /// <param name="position">The relative position of the OpenIddict module in the ASP.NET Core pipeline.</param>
        /// <param name="registration">The delegate used to register the module in the ASP.NET Core pipeline.</param>
        /// <returns>The<see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddModule(
            [NotNull] string name, int position,
            [NotNull] Action<IApplicationBuilder> registration) {
            if (string.IsNullOrEmpty(name)) {
                throw new ArgumentNullException(nameof(name));
            }

            if (registration == null) {
                throw new ArgumentNullException(nameof(registration));
            }

            return Configure(options => {
                if (options.Modules.Any(module => module.Name == name)) {
                    return;
                }

                options.Modules.Add(new OpenIddictModule(name, position, registration));
            });
        }

        /// <summary>
        /// Registers a new ephemeral key used to sign the tokens issued by OpenIddict: the key
        /// is discarded when the application shuts down and tokens signed using this key are
        /// automatically invalidated. This method should only be used during development:
        /// on production, using a X.509 certificate stored in the machine store is recommended.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder AddEphemeralSigningKey() {
            // Note: a 1024-bit key might be returned by RSA.Create() on .NET Desktop/Mono,
            // where RSACryptoServiceProvider is still the default implementation and
            // where custom implementations can be registered via CryptoConfig.
            // To ensure the key size is always acceptable, replace it if necessary.
            var algorithm = RSA.Create();

            if (algorithm.KeySize < 2048) {
                algorithm.KeySize = 2048;
            }

#if NET451
            // Note: RSACng cannot be used as it's not available on Mono.
            if (algorithm.KeySize < 2048 && algorithm is RSACryptoServiceProvider) {
                algorithm.Dispose();
                algorithm = new RSACryptoServiceProvider(2048);
            }
#endif

            if (algorithm.KeySize < 2048) {
                throw new InvalidOperationException("The ephemeral key generation failed.");
            }

            // Note: the RSA instance cannot be flowed as-is due to a bug in IdentityModel that disposes
            // the underlying algorithm when it can be cast to RSACryptoServiceProvider. To work around
            // this bug, the RSA public/private parameters are manually exported and re-imported when needed.
            SecurityKey key;
#if NET451
            if (algorithm is RSACryptoServiceProvider) {
                var parameters = algorithm.ExportParameters(includePrivateParameters: true);
                key = new RsaSecurityKey(parameters);

                // Dispose the algorithm instance.
                algorithm.Dispose();
            }

            else {
#endif
                key = new RsaSecurityKey(algorithm);
#if NET451
            }
#endif

            return Configure(options => options.SigningCredentials.AddKey(key));
        }

        /// <summary>
        /// Registers a <see cref="X509Certificate2"/> used to sign the tokens issued by OpenIddict.
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
        /// Registers a <see cref="X509Certificate2"/> retrieved from
        /// an embedded resource to sign the tokens issued by OpenIddict.
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
        /// Registers a <see cref="X509Certificate2"/> extracted
        /// from a stream to sign the tokens issued by OpenIddict.
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
        /// Registers a <see cref="X509Certificate2"/> extracted
        /// from a stream to sign the tokens issued by OpenIddict.
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
        /// Registers a <see cref="X509Certificate2"/> retrieved from the
        /// X.509 machine store to sign the tokens issued by OpenIddict.
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
        /// Registers a <see cref="X509Certificate2"/> retrieved from the
        /// given X.509 store to sign the tokens issued by OpenIddict.
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
            return Configure(options => options.AuthorizationEndpointPath = path);
        }

        /// <summary>
        /// Enables the introspection endpoint.
        /// </summary>
        /// <param name="path">The relative path of the logout endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableIntrospectionEndpoint(PathString path) {
            return Configure(options => options.IntrospectionEndpointPath = path);
        }

        /// <summary>
        /// Enables the logout endpoint.
        /// </summary>
        /// <param name="path">The relative path of the logout endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableLogoutEndpoint(PathString path) {
            return Configure(options => options.LogoutEndpointPath = path);
        }

        /// <summary>
        /// Enables the revocation endpoint.
        /// </summary>
        /// <param name="path">The relative path of the revocation endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableRevocationEndpoint(PathString path) {
            return Configure(options => options.RevocationEndpointPath = path);
        }

        /// <summary>
        /// Enables the token endpoint.
        /// </summary>
        /// <param name="path">The relative path of the token endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableTokenEndpoint(PathString path) {
            return Configure(options => options.TokenEndpointPath = path);
        }

        /// <summary>
        /// Enables the userinfo endpoint.
        /// </summary>
        /// <param name="path">The relative path of the userinfo endpoint.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder EnableUserinfoEndpoint(PathString path) {
            return Configure(options => options.UserinfoEndpointPath = path);
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
        /// Sets JWT as the default token format for access tokens.
        /// </summary>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public virtual OpenIddictBuilder UseJsonWebTokens() {
            return Configure(options => options.AccessTokenHandler = new JwtSecurityTokenHandler());
        }
    }
}