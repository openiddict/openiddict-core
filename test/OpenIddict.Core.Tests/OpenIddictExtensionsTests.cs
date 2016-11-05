using System;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Builder.Internal;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Infrastructure;
using Xunit;

namespace OpenIddict.Core.Tests {
    public class OpenIddictExtensionsTests {
        [Fact]
        public void AddOpenIddict_ProviderIsRegistered() {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<object, object, object, object>();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictOptions>>();

            // Assert
            Assert.IsType(typeof(OpenIddictProvider<object, object, object, object>), options.Value.Provider);
        }

        [Theory]
        [InlineData(typeof(IDataProtectionProvider))]
        [InlineData(typeof(IDistributedCache))]
        [InlineData(typeof(OpenIddictApplicationManager<object>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<object>))]
        [InlineData(typeof(OpenIddictScopeManager<object>))]
        [InlineData(typeof(OpenIddictTokenManager<object>))]
        [InlineData(typeof(OpenIddictServices<object, object, object, object>))]
        public void AddOpenIddict_BasicServicesAreRegistered(Type type) {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<object, object, object, object>();

            // Assert
            Assert.Contains(services, service => service.ServiceType == type);
        }

        [Fact]
        public void UseOpenIddict_AnExceptionIsThrownWhenNoSigningCredentialsIsRegistered() {
            // Arrange
            var services = new ServiceCollection();
            services.AddOpenIddict<object, object, object, object>();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("At least one signing key must be registered. Consider registering a X.509 " +
                         "certificate using 'services.AddOpenIddict().AddSigningCertificate()' or call " +
                         "'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.", exception.Message);
        }

        [Fact]
        public void UseOpenIddict_AnExceptionIsThrownWhenNoFlowIsEnabled() {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict<object, object, object, object>()
                .AddEphemeralSigningKey();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddict());

            Assert.Equal("At least one OAuth2/OpenID Connect flow must be enabled.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit)]
        public void UseOpenIddict_AnExceptionIsThrownWhenAuthorizationEndpointIsDisabled(string flow) {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict<object, object, object, object>()
                .AddEphemeralSigningKey()
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
        public void UseOpenIddict_AnExceptionIsThrownWhenTokenEndpointIsDisabled(string flow) {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict<object, object, object, object>()
                .AddEphemeralSigningKey()
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
        public void UseOpenIddict_OpenIdConnectServerMiddlewareIsRegistered() {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict<object, object, object, object>()
                .AddEphemeralSigningKey()
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
