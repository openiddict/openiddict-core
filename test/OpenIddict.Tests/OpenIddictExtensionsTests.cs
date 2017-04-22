using System;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace OpenIddict.Tests
{
    public class OpenIddictExtensionsTests
    {
        [Fact]
        public void Configure_OptionsAreCorrectlyAmended()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.Configure(configuration => configuration.AccessTokenLifetime = TimeSpan.FromDays(1));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromDays(1), options.AccessTokenLifetime);
        }

        [Fact]
        public void AddEphemeralSigningKey_SigningKeyIsCorrectlyAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddEphemeralSigningKey();

            var options = GetOptions(services);

            // Assert
            Assert.Equal(1, options.SigningCredentials.Count);
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
        public void AddEphemeralSigningKey_SigningCredentialsUseSpecifiedAlgorithm(string algorithm)
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddEphemeralSigningKey(algorithm);

            var options = GetOptions(services);
            var credentials = options.SigningCredentials[0];

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
        public void AddSigningKey_SigningKeyIsCorrectlyAdded(string algorithm)
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            var factory = Mock.Of<CryptoProviderFactory>(mock =>
                mock.IsSupportedAlgorithm(algorithm, It.IsAny<SecurityKey>()));

            var key = Mock.Of<SecurityKey>(mock => mock.CryptoProviderFactory == factory);

            // Act
            builder.AddSigningKey(key);

            var options = GetOptions(services);

            // Assert
            Assert.Same(key, options.SigningCredentials[0].Key);
        }

        [Fact]
        public void AddSigningCertificate_SigningKeyIsCorrectlyAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddSigningCertificate(
                assembly: typeof(OpenIddictExtensionsTests).GetTypeInfo().Assembly,
                resource: "OpenIddict.Tests.Certificate.pfx",
                password: "OpenIddict");

            var options = GetOptions(services);

            // Assert
            Assert.IsType<X509SecurityKey>(options.SigningCredentials[0].Key);
        }

        [Fact]
        public void AllowAuthorizationCodeFlow_CodeFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowAuthorizationCodeFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.AuthorizationCode, options.GrantTypes);
        }

        [Fact]
        public void AllowClientCredentialsFlow_ClientCredentialsFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowClientCredentialsFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.ClientCredentials, options.GrantTypes);
        }

        [Fact]
        public void AllowCustomFlow_CustomFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

            var options = GetOptions(services);

            // Assert
            Assert.Contains("urn:ietf:params:oauth:grant-type:custom_grant", options.GrantTypes);
        }

        [Fact]
        public void AllowImplicitFlow_ImplicitFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowImplicitFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.Implicit, options.GrantTypes);
        }

        [Fact]
        public void AllowPasswordFlow_PasswordFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowPasswordFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.Password, options.GrantTypes);
        }

        [Fact]
        public void AllowRefreshTokenFlow_RefreshTokenFlowIsAddedToGrantTypes()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AllowRefreshTokenFlow();

            var options = GetOptions(services);

            // Assert
            Assert.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken, options.GrantTypes);
        }

        [Fact]
        public void DisableConfigurationEndpoint_ConfigurationEndpointIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableConfigurationEndpoint();

            var options = GetOptions(services);

            // Assert
            Assert.Equal(PathString.Empty, options.ConfigurationEndpointPath);
        }

        [Fact]
        public void DisableCryptographyEndpoint_CryptographyEndpointIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableCryptographyEndpoint();

            var options = GetOptions(services);

            // Assert
            Assert.Equal(PathString.Empty, options.CryptographyEndpointPath);
        }

        [Fact]
        public void DisableSlidingExpiration_SlidingExpirationIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableSlidingExpiration();

            var options = GetOptions(services);

            // Assert
            Assert.False(options.UseSlidingExpiration);
        }

        [Fact]
        public void DisableTokenRevocation_TokenRevocationIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.DisableTokenRevocation();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.DisableTokenRevocation);
        }

        [Fact]
        public void EnableAuthorizationEndpoint_AuthorizationEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableAuthorizationEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.AuthorizationEndpointPath);
        }

        [Fact]
        public void EnableIntrospectionEndpoint_IntrospectionEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableIntrospectionEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.IntrospectionEndpointPath);
        }

        [Fact]
        public void EnableLogoutEndpoint_LogoutEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableLogoutEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.LogoutEndpointPath);
        }

        [Fact]
        public void EnableRequestCaching_RequestCachingIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableRequestCaching();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.EnableRequestCaching);
        }

        [Fact]
        public void EnableRevocationEndpoint_RevocationEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableRevocationEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.RevocationEndpointPath);
        }

        [Fact]
        public void EnableTokenEndpoint_TokenEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableTokenEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.TokenEndpointPath);
        }

        [Fact]
        public void EnableUserinfoEndpoint_UserinfoEndpointIsEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.EnableUserinfoEndpoint("/endpoint-path");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("/endpoint-path", options.UserinfoEndpointPath);
        }

        [Fact]
        public void RequireClientIdentification_ClientIdentificationIsEnforced()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.RequireClientIdentification();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.RequireClientIdentification);
        }

        [Fact]
        public void SetAccessTokenLifetime_DefaultAccessTokenLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetAccessTokenLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.AccessTokenLifetime);
        }

        [Fact]
        public void SetAuthorizationCodeLifetime_DefaultAuthorizationCodeLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.AuthorizationCodeLifetime);
        }

        [Fact]
        public void SetIdentityTokenLifetime_DefaultIdentityTokenLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetIdentityTokenLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.IdentityTokenLifetime);
        }

        [Fact]
        public void SetRefreshTokenLifetime_DefaultRefreshTokenLifetimeIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetRefreshTokenLifetime(TimeSpan.FromMinutes(42));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(TimeSpan.FromMinutes(42), options.RefreshTokenLifetime);
        }

        [Fact]
        public void SetIssuer_AddressIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.SetIssuer(new Uri("http://www.fabrikam.com/"));

            var options = GetOptions(services);

            // Assert
            Assert.Equal(new Uri("http://www.fabrikam.com/"), options.Issuer);
        }

        [Fact]
        public void UseDataProtectionProvider_DefaultProviderIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.UseDataProtectionProvider(new EphemeralDataProtectionProvider(new LoggerFactory()));

            var options = GetOptions(services);

            // Assert
            Assert.IsType<EphemeralDataProtectionProvider>(options.DataProtectionProvider);
        }

        [Fact]
        public void UseJsonWebTokens_AccessTokenHandlerIsCorrectlySet()
        {
            // Arrange
            var services = CreateServices();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.UseJsonWebTokens();

            var options = GetOptions(services);

            // Assert
            Assert.IsType<JwtSecurityTokenHandler>(options.AccessTokenHandler);
        }

        private static IServiceCollection CreateServices()
        {
            var services = new ServiceCollection();
            services.AddAuthentication();
            services.AddDistributedMemoryCache();
            services.AddLogging();
            services.AddSingleton<IHostingEnvironment, HostingEnvironment>();

            return services;
        }

        private static OpenIddictOptions GetOptions(IServiceCollection services)
        {
            services.RemoveAll<IPostConfigureOptions<OpenIdConnectServerOptions>>();
            services.RemoveAll<IPostConfigureOptions<OpenIddictOptions>>();

            var provider = services.BuildServiceProvider();

            var options = provider.GetRequiredService<IOptionsSnapshot<OpenIddictOptions>>();
            return options.Get(OpenIdConnectServerDefaults.AuthenticationScheme);
        }
    }
}
