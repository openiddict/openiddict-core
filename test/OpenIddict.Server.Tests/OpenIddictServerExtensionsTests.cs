/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Builder.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictServerExtensionsTests
    {
        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenNoFlowIsEnabled()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                });

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("At least one OAuth2/OpenID Connect flow must be enabled.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit)]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenAuthorizationEndpointIsDisabled(string flow)
        {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .Configure(options => options.GrantTypes.Add(flow))
                    .Configure(options => options.AuthorizationEndpointPath = PathString.Empty);

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("The authorization endpoint must be enabled to use " +
                         "the authorization code and implicit flows.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Password)]
        [InlineData(OpenIdConnectConstants.GrantTypes.RefreshToken)]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenTokenEndpointIsDisabled(string flow)
        {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .EnableAuthorizationEndpoint("/connect/authorize")
                    .Configure(options => options.GrantTypes.Add(flow))
                    .Configure(options => options.TokenEndpointPath = PathString.Empty);

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("The token endpoint must be enabled to use the authorization code, " +
                         "client credentials, password and refresh token flows.", exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenTokenRevocationIsDisabled()
        {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .EnableAuthorizationEndpoint("/connect/authorize")
                    .EnableRevocationEndpoint("/connect/revocation")
                    .AllowImplicitFlow()
                    .DisableTokenRevocation();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("The revocation endpoint cannot be enabled when token revocation is disabled.", exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenUsingReferenceTokensWithTokenRevocationDisabled()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddDataProtection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .EnableAuthorizationEndpoint("/connect/authorize")
                    .AllowImplicitFlow()
                    .DisableTokenRevocation()
                    .UseReferenceTokens();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("Reference tokens cannot be used when disabling token revocation.", exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenUsingReferenceTokensIfAnAccessTokenHandlerIsSet()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddDataProtection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .EnableAuthorizationEndpoint("/connect/authorize")
                    .AllowImplicitFlow()
                    .UseReferenceTokens()
                    .UseJsonWebTokens();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("Reference tokens cannot be used when configuring JWT as the access token format.", exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenUsingSlidingExpirationWithoutRollingTokensAndWithTokenRevocationDisabled()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddDataProtection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .EnableAuthorizationEndpoint("/connect/authorize")
                    .AllowImplicitFlow()
                    .DisableTokenRevocation();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("Sliding expiration must be disabled when turning off " +
                         "token revocation if rolling tokens are not used.", exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenNoSigningKeyIsRegisteredIfTheImplicitFlowIsEnabled()
        {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .EnableAuthorizationEndpoint("/connect/authorize")
                    .AllowImplicitFlow();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("At least one asymmetric signing key must be registered when enabling the implicit flow. " +
                         "Consider registering a X.509 certificate using 'services.AddOpenIddict().AddSigningCertificate()' " +
                         "or call 'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.", exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_OpenIdConnectServerMiddlewareIsRegistered()
        {
            // Arrange
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.SetDefaultApplicationEntity<OpenIddictApplication>()
                           .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                           .SetDefaultScopeEntity<OpenIddictScope>()
                           .SetDefaultTokenEntity<OpenIddictToken>();
                })

                .AddServer()
                    .AddSigningCertificate(
                        assembly: typeof(OpenIddictServerProviderTests).GetTypeInfo().Assembly,
                        resource: "OpenIddict.Server.Tests.Certificate.pfx",
                        password: "OpenIddict")
                    .AllowImplicitFlow()
                    .EnableAuthorizationEndpoint("/connect/authorize");

            var builder = new Mock<IApplicationBuilder>();
            builder.SetupGet(mock => mock.ApplicationServices)
                .Returns(services.BuildServiceProvider());

            // Act
            builder.Object.UseOpenIddictServer();

            // Assert
            builder.Verify(mock => mock.Use(It.IsAny<Func<RequestDelegate, RequestDelegate>>()), Times.Once());
        }

        public class OpenIddictApplication { }
        public class OpenIddictAuthorization { }
        public class OpenIddictScope { }
        public class OpenIddictToken { }
    }
}
