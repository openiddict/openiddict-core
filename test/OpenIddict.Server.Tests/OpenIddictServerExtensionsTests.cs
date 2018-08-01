/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using System.Text;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Builder.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictServerExtensionsTests
    {
        public void AddServer_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.AddServer());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void AddServer_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.AddServer(configuration: null));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void AddServer_RegistersCachingServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IDistributedCache));
            Assert.Contains(services, service => service.ServiceType == typeof(IMemoryCache));
        }

        [Fact]
        public void AddServer_RegistersLoggingServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(ILogger<>));
        }

        [Fact]
        public void AddServer_RegistersOptionsServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IOptions<>));
        }

        [Fact]
        public void AddServer_RegistersEventService()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(IOpenIddictServerEventService) &&
                                                 service.ImplementationType == typeof(OpenIddictServerEventService));
        }

        [Fact]
        public void AddServer_CanBeSafelyInvokedMultipleTimes()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act and assert
            builder.AddServer();
            builder.AddServer();
            builder.AddServer();
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenProviderIsNull()
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
                    .Configure(options => options.Provider = null);

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in server provider.")
                .AppendLine("This error may indicate that 'OpenIddictServerOptions.Provider' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddServer().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenProviderTypeIsIncompatible()
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
                    .Configure(options => options.Provider = new OpenIdConnectServerProvider());

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in server provider.")
                .AppendLine("This error may indicate that 'OpenIddictServerOptions.Provider' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddServer().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }

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
                })

                .AddServer();

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
        public void UseOpenIddictServer_ThrowsAnExceptionWhenTokenStorageIsDisabled()
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
                    .DisableTokenStorage();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("The revocation endpoint cannot be enabled when token storage is disabled.", exception.Message);
        }

        [Fact]
        public void UseOpenIddictServer_ThrowsAnExceptionWhenUsingReferenceTokensWithTokenStorageDisabled()
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
                    .DisableTokenStorage()
                    .UseReferenceTokens();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("Reference tokens cannot be used when disabling token storage.", exception.Message);
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
        public void UseOpenIddictServer_ThrowsAnExceptionWhenUsingSlidingExpirationWithoutRollingTokensAndWithTokenStorageDisabled()
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
                    .DisableTokenStorage();

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictServer());

            Assert.Equal("Sliding expiration must be disabled when turning off " +
                         "token storage if rolling tokens are not used.", exception.Message);
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

            Assert.Equal(new StringBuilder()
                .AppendLine("At least one asymmetric signing key must be registered when enabling the implicit flow.")
                .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                .ToString(), exception.Message);
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
