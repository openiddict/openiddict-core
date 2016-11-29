using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace OpenIddict.Tests {
    public class OpenIddictBuilderTests {
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
                assembly: typeof(OpenIddictBuilderTests).GetTypeInfo().Assembly,
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
    }
}
