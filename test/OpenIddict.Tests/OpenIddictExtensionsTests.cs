using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Builder.Internal;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace OpenIddict.Tests {
    public class OpenIddictExtensionsTests {
        [Fact]
        public void UseOpenIddict_ThrowsAnExceptionWhenServicesAreNotRegistered() {
            // Arrange
            var services = new ServiceCollection();
            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("The OpenIddict services cannot be resolved from the dependency injection container. " +
                         "Make sure 'services.AddOpenIddict()' is correctly called from 'ConfigureServices()'.", exception.Message);
        }

        [Fact]
        public void UseOpenIddict_ThrowsAnExceptionWhenNoDistributedCacheIsRegisteredIfRequestCachingIsEnabled() {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .EnableRequestCaching();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("A distributed cache implementation must be registered in the OpenIddict options " +
                         "or in the dependency injection container when enabling request caching support.", exception.Message);
        }

        [Fact]
        public void UseOpenIddict_ThrowsAnExceptionWhenNoSigningCredentialsIsRegistered() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOpenIddict();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("At least one signing key must be registered. Consider registering a X.509 " +
                         "certificate using 'services.AddOpenIddict().AddSigningCertificate()' or call " +
                         "'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.", exception.Message);
        }

        [Fact]
        public void UseOpenIddict_ThrowsAnExceptionWhenNoFlowIsEnabled() {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddSigningCertificate(
                    assembly: typeof(OpenIddictProviderTests).GetTypeInfo().Assembly,
                    resource: "OpenIddict.Tests.Certificate.pfx",
                    password: "OpenIddict");

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("At least one OAuth2/OpenID Connect flow must be enabled.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit)]
        public void UseOpenIddict_ThrowsAnExceptionWhenAuthorizationEndpointIsDisabled(string flow) {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddSigningCertificate(
                    assembly: typeof(OpenIddictProviderTests).GetTypeInfo().Assembly,
                    resource: "OpenIddict.Tests.Certificate.pfx",
                    password: "OpenIddict")
                .Configure(options => options.GrantTypes.Add(flow))
                .Configure(options => options.AuthorizationEndpointPath = PathString.Empty);

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("The authorization endpoint must be enabled to use " +
                         "the authorization code and implicit flows.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Password)]
        [InlineData(OpenIdConnectConstants.GrantTypes.RefreshToken)]
        public void UseOpenIddict_ThrowsAnExceptionWhenTokenEndpointIsDisabled(string flow) {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddSigningCertificate(
                    assembly: typeof(OpenIddictProviderTests).GetTypeInfo().Assembly,
                    resource: "OpenIddict.Tests.Certificate.pfx",
                    password: "OpenIddict")
                .EnableAuthorizationEndpoint("/connect/authorize")
                .Configure(options => options.GrantTypes.Add(flow))
                .Configure(options => options.TokenEndpointPath = PathString.Empty);

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("The token endpoint must be enabled to use the authorization code, " +
                         "client credentials, password and refresh token flows.", exception.Message);
        }

        [Fact]
        public void UseOpenIddict_ThrowsAnExceptionWhenTokenRevocationIsDisabled() {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddSigningCertificate(
                    assembly: typeof(OpenIddictProviderTests).GetTypeInfo().Assembly,
                    resource: "OpenIddict.Tests.Certificate.pfx",
                    password: "OpenIddict")
                .EnableAuthorizationEndpoint("/connect/authorize")
                .EnableRevocationEndpoint("/connect/revocation")
                .AllowImplicitFlow()
                .DisableTokenRevocation();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("The revocation endpoint cannot be enabled when token revocation is disabled.", exception.Message);
        }

        [Fact]
        public void Configure_OptionsAreCorrectlyAmended() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.Configure(configuration => configuration.Description.DisplayName = "OpenIddict");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal("OpenIddict", options.Value.Description.DisplayName);
        }

        [Fact]
        public void UseOpenIddict_OpenIdConnectServerMiddlewareIsRegistered() {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddSigningCertificate(
                    assembly: typeof(OpenIddictProviderTests).GetTypeInfo().Assembly,
                    resource: "OpenIddict.Tests.Certificate.pfx",
                    password: "OpenIddict")
                .AllowImplicitFlow()
                .EnableAuthorizationEndpoint("/connect/authorize");

            var builder = new Mock<IApplicationBuilder>();
            builder.SetupGet(mock => mock.ApplicationServices)
                .Returns(services.BuildServiceProvider());

            // Act
            builder.Object.UseOpenIddict();

            // Assert
            builder.Verify(mock => mock.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()), Times.Once());
        }

        [Fact]
        public void AddEphemeralSigningKey_SigningKeyIsCorrectlyAdded() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddEphemeralSigningKey();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(1, options.Value.SigningCredentials.Count);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.RsaSha256Signature)]
        [InlineData(SecurityAlgorithms.RsaSha384Signature)]
        [InlineData(SecurityAlgorithms.RsaSha512Signature)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
#endif
        public void AddEphemeralSigningKey_SigningCredentialsUseSpecifiedAlgorithm(string algorithm) {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddEphemeralSigningKey(algorithm);

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();
            var credentials = options.Value.SigningCredentials[0];

            // Assert
            Assert.Equal(algorithm, credentials.Algorithm);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256Signature)]
        [InlineData(SecurityAlgorithms.RsaSha256Signature)]
#if SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
#endif
        public void AddSigningKey_SigningKeyIsCorrectlyAdded(string algorithm) {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            var factory = Mock.Of<CryptoProviderFactory>(mock =>
                mock.IsSupportedAlgorithm(algorithm, It.IsAny<SecurityKey>()));

            var key = Mock.Of<SecurityKey>(mock => mock.CryptoProviderFactory == factory);

            // Act
            builder.AddSigningKey(key);

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Same(key, options.Value.SigningCredentials[0].Key);
        }

        [Fact]
        public void AddSigningCertificate_SigningKeyIsCorrectlyAdded() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddSigningCertificate(
                assembly: typeof(OpenIddictExtensionsTests).GetTypeInfo().Assembly,
                resource: "OpenIddict.Tests.Certificate.pfx",
                password: "OpenIddict");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.IsType(typeof(X509SecurityKey), options.Value.SigningCredentials[0].Key);
        }

        [Fact]
        public void AllowAuthorizationCodeFlow_CodeFlowIsAddedToGrantTypes() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowAuthorizationCodeFlow();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode, options.Value.GrantTypes);
        }

        [Fact]
        public void AllowClientCredentialsFlow_ClientCredentialsFlowIsAddedToGrantTypes() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowClientCredentialsFlow();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.ClientCredentials, options.Value.GrantTypes);
        }

        [Fact]
        public void AllowCustomFlow_CustomFlowIsAddedToGrantTypes() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Contains("urn:ietf:params:oauth:grant-type:custom_grant", options.Value.GrantTypes);
        }

        [Fact]
        public void AllowImplicitFlow_ImplicitFlowIsAddedToGrantTypes() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowImplicitFlow();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.Implicit, options.Value.GrantTypes);
        }

        [Fact]
        public void AllowPasswordFlow_PasswordFlowIsAddedToGrantTypes() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowPasswordFlow();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.Password, options.Value.GrantTypes);
        }

        [Fact]
        public void AllowRefreshTokenFlow_RefreshTokenFlowIsAddedToGrantTypes() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowRefreshTokenFlow();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken, options.Value.GrantTypes);
        }

        [Fact]
        public void DisableConfigurationEndpoint_ConfigurationEndpointIsDisabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableConfigurationEndpoint();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(PathString.Empty, options.Value.ConfigurationEndpointPath);
        }

        [Fact]
        public void DisableCryptographyEndpoint_CryptographyEndpointIsDisabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableCryptographyEndpoint();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(PathString.Empty, options.Value.CryptographyEndpointPath);
        }

        [Fact]
        public void DisableSlidingExpiration_SlidingExpirationIsDisabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableSlidingExpiration();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.False(options.Value.UseSlidingExpiration);
        }

        [Fact]
        public void DisableTokenRevocation_TokenRevocationIsDisabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableTokenRevocation();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.True(options.Value.DisableTokenRevocation);
        }

        [Fact]
        public void EnableAuthorizationEndpoint_AuthorizationEndpointIsEnabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableAuthorizationEndpoint("/endpoint-path");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal("/endpoint-path", options.Value.AuthorizationEndpointPath);
        }

        [Fact]
        public void EnableIntrospectionEndpoint_IntrospectionEndpointIsEnabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableIntrospectionEndpoint("/endpoint-path");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal("/endpoint-path", options.Value.IntrospectionEndpointPath);
        }

        [Fact]
        public void EnableLogoutEndpoint_LogoutEndpointIsEnabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableLogoutEndpoint("/endpoint-path");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal("/endpoint-path", options.Value.LogoutEndpointPath);
        }

        [Fact]
        public void EnableRequestCaching_RequestCachingIsEnabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableRequestCaching();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.True(options.Value.EnableRequestCaching);
        }

        [Fact]
        public void EnableRevocationEndpoint_RevocationEndpointIsEnabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableRevocationEndpoint("/endpoint-path");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal("/endpoint-path", options.Value.RevocationEndpointPath);
        }

        [Fact]
        public void EnableTokenEndpoint_TokenEndpointIsEnabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableTokenEndpoint("/endpoint-path");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal("/endpoint-path", options.Value.TokenEndpointPath);
        }

        [Fact]
        public void EnableUserinfoEndpoint_UserinfoEndpointIsEnabled() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableUserinfoEndpoint("/endpoint-path");

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal("/endpoint-path", options.Value.UserinfoEndpointPath);
        }

        [Fact]
        public void RequireClientIdentification_ClientIdentificationIsEnforced() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.RequireClientIdentification();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.True(options.Value.RequireClientIdentification);
        }

        [Fact]
        public void SetAccessTokenLifetime_DefaultAccessTokenLifetimeIsReplaced() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetAccessTokenLifetime(TimeSpan.FromMinutes(42));

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.Value.AccessTokenLifetime);
        }

        [Fact]
        public void SetAuthorizationCodeLifetime_DefaultAuthorizationCodeLifetimeIsReplaced() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(42));

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.Value.AuthorizationCodeLifetime);
        }

        [Fact]
        public void SetIdentityTokenLifetime_DefaultIdentityTokenLifetimeIsReplaced() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetIdentityTokenLifetime(TimeSpan.FromMinutes(42));

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.Value.IdentityTokenLifetime);
        }

        [Fact]
        public void SetRefreshTokenLifetime_DefaultRefreshTokenLifetimeIsReplaced() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetRefreshTokenLifetime(TimeSpan.FromMinutes(42));

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.Value.RefreshTokenLifetime);
        }

        [Fact]
        public void SetIssuer_AddressIsReplaced() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetIssuer(new Uri("http://www.fabrikam.com/"));

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.Equal(new Uri("http://www.fabrikam.com/"), options.Value.Issuer);
        }

        [Fact]
        public void UseDataProtectionProvider_DefaultProviderIsReplaced() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.UseDataProtectionProvider(new EphemeralDataProtectionProvider());

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.IsType(typeof(EphemeralDataProtectionProvider), options.Value.DataProtectionProvider);
        }

        [Fact]
        public void UseJsonWebTokens_AccessTokenHandlerIsCorrectlySet() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.UseJsonWebTokens();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.IsType(typeof(JwtSecurityTokenHandler), options.Value.AccessTokenHandler);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void IsAuthorizationCodeFlowEnabled_ReturnsAppropriateResult(bool enabled) {
            // Arrange
            var options = new OpenIddictOptions();

            if (enabled) {
                options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.AuthorizationCode);
            }

            // Act and assert
            Assert.Equal(enabled, options.IsAuthorizationCodeFlowEnabled());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void IsClientCredentialsFlowEnabled_ReturnsAppropriateResult(bool enabled) {
            // Arrange
            var options = new OpenIddictOptions();

            if (enabled) {
                options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.ClientCredentials);
            }

            // Act and assert
            Assert.Equal(enabled, options.IsClientCredentialsFlowEnabled());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void IsImplicitFlowEnabled_ReturnsAppropriateResult(bool enabled) {
            // Arrange
            var options = new OpenIddictOptions();

            if (enabled) {
                options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Implicit);
            }

            // Act and assert
            Assert.Equal(enabled, options.IsImplicitFlowEnabled());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void IsPasswordFlowEnabled_ReturnsAppropriateResult(bool enabled) {
            // Arrange
            var options = new OpenIddictOptions();

            if (enabled) {
                options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.Password);
            }

            // Act and assert
            Assert.Equal(enabled, options.IsPasswordFlowEnabled());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void IsRefreshTokenFlowEnabled_ReturnsAppropriateResult(bool enabled) {
            // Arrange
            var options = new OpenIddictOptions();

            if (enabled) {
                options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.RefreshToken);
            }

            // Act and assert
            Assert.Equal(enabled, options.IsRefreshTokenFlowEnabled());
        }
    }
}
