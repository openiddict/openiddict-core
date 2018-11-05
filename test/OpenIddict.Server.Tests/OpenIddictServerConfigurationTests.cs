/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictServerConfigurationTests
    {
        [Fact]
        public void Configure_ThrowsAnExceptionForNullOptions()
        {
            // Arrange
            var configuration = new OpenIddictServerConfiguration(
                Mock.Of<IDistributedCache>(),
                Mock.Of<IDataProtectionProvider>());

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => configuration.Configure(null));

            Assert.Equal("options", exception.ParamName);
        }

        [Fact]
        public void Configure_ThrowsAnExceptionWhenSchemeIsAlreadyRegisteredWithDifferentHandlerType()
        {
            // Arrange
            var options = new AuthenticationOptions();
            options.AddScheme(OpenIddictServerDefaults.AuthenticationScheme, builder =>
            {
                builder.HandlerType = typeof(OpenIdConnectServerHandler);
            });

            var configuration = new OpenIddictServerConfiguration(
                Mock.Of<IDistributedCache>(),
                Mock.Of<IDataProtectionProvider>());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => configuration.Configure(options));

            Assert.Equal(new StringBuilder()
                .AppendLine("The OpenIddict server handler cannot be registered as an authentication scheme.")
                .AppendLine("This may indicate that an instance of the OpenID Connect server was registered.")
                .Append("Make sure that 'services.AddAuthentication().AddOpenIdConnectServer()' is not used.")
                .ToString(), exception.Message);
        }

        [Theory]
        [InlineData(new object[] { new string[] { OpenIddictServerDefaults.AuthenticationScheme, null, null, null, null, null } })]
        [InlineData(new object[] { new string[] { null, OpenIddictServerDefaults.AuthenticationScheme, null, null, null, null } })]
        [InlineData(new object[] { new string[] { null, null, OpenIddictServerDefaults.AuthenticationScheme, null, null, null } })]
        [InlineData(new object[] { new string[] { null, null, null, OpenIddictServerDefaults.AuthenticationScheme, null, null } })]
        [InlineData(new object[] { new string[] { null, null, null, null, OpenIddictServerDefaults.AuthenticationScheme, null } })]
        [InlineData(new object[] { new string[] { null, null, null, null, null, OpenIddictServerDefaults.AuthenticationScheme } })]
        public void PostConfigure_ThrowsAnExceptionWhenDefaultSchemesPointToServerHandler(string[] schemes)
        {
            // Arrange
            var options = new AuthenticationOptions
            {
                DefaultAuthenticateScheme = schemes[0],
                DefaultChallengeScheme = schemes[1],
                DefaultForbidScheme = schemes[2],
                DefaultScheme = schemes[3],
                DefaultSignInScheme = schemes[4],
                DefaultSignOutScheme = schemes[5]
            };

            options.AddScheme<OpenIddictServerHandler>(OpenIddictServerDefaults.AuthenticationScheme, displayName: null);

            var configuration = new OpenIddictServerConfiguration(
                Mock.Of<IDistributedCache>(),
                Mock.Of<IDataProtectionProvider>());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => configuration.PostConfigure(Options.DefaultName, options));

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendLine("The OpenIddict server handler cannot be used as the default scheme handler.")
                .Append("Make sure that neither DefaultAuthenticateScheme, DefaultChallengeScheme, ")
                .Append("DefaultForbidScheme, DefaultSignInScheme, DefaultSignOutScheme nor DefaultScheme ")
                .Append("point to an instance of the OpenIddict server handler.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenRandomNumberGeneratorIsNull()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.RandomNumberGenerator = null);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal("A random number generator must be registered.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenProviderTypeIsNull()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.ProviderType = null);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in server provider.")
                .AppendLine("This error may indicate that 'OpenIddictServerOptions.ProviderType' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddServer().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenProviderTypeIsIncompatible()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.ProviderType = typeof(OpenIdConnectServerProvider));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in server provider.")
                .AppendLine("This error may indicate that 'OpenIddictServerOptions.ProviderType' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddServer().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenNoFlowIsEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal("At least one OAuth2/OpenID Connect flow must be enabled.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictConstants.GrantTypes.Implicit)]
        public async Task PostConfigure_ThrowsAnExceptionWhenAuthorizationEndpointIsDisabled(string flow)
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.GrantTypes.Add(flow))
                       .Configure(options => options.AuthorizationEndpointPath = PathString.Empty);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The authorization endpoint must be enabled to use the authorization code and implicit flows.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIddictConstants.GrantTypes.Password)]
        [InlineData(OpenIddictConstants.GrantTypes.RefreshToken)]
        public async Task PostConfigure_ThrowsAnExceptionWhenTokenEndpointIsDisabled(string flow)
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .Configure(options => options.GrantTypes.Add(flow))
                       .Configure(options => options.TokenEndpointPath = PathString.Empty);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The token endpoint must be enabled to use the authorization code, " +
                         "client credentials, password and refresh token flows.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenCachingPolicyIsNullAndRequestCachingEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .AllowImplicitFlow()
                       .EnableRequestCaching();

                builder.Configure(options => options.RequestCachingPolicy = null);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("A caching policy must be specified when enabling request caching.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenTokenStorageIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .EnableRevocationEndpoint("/connect/revocation")
                       .AllowImplicitFlow()
                       .DisableTokenStorage();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The revocation endpoint cannot be enabled when token storage is disabled.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenUsingReferenceTokensWithTokenStorageDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .AllowImplicitFlow()
                       .DisableTokenStorage()
                       .UseReferenceTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("Reference tokens cannot be used when disabling token storage.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenUsingSlidingExpirationWithoutRollingTokensAndWithTokenStorageDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .AllowImplicitFlow()
                       .DisableTokenStorage();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("Sliding expiration must be disabled when turning off " +
                         "token storage if rolling tokens are not used.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenUsingReferenceTokensIfAnAccessTokenHandlerIsSet()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .AllowImplicitFlow()
                       .UseReferenceTokens()
                       .UseJsonWebTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("Reference tokens cannot be used when configuring JWT as the access token format.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenNoSigningKeyIsRegisteredIfAnAccessTokenHandlerIsSet()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .EnableTokenEndpoint("/connect/token")
                       .AllowAuthorizationCodeFlow()
                       .UseJsonWebTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("At least one signing key must be registered when using JWT as the access token format.")
                .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenNoSigningKeyIsRegisteredIfTheImplicitFlowIsEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .AllowImplicitFlow();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("At least one asymmetric signing key must be registered when enabling the implicit flow.")
                .Append("Consider registering a certificate using 'services.AddOpenIddict().AddServer().AddSigningCertificate()' ")
                .Append("or 'services.AddOpenIddict().AddServer().AddDevelopmentSigningCertificate()' or call ")
                .Append("'services.AddOpenIddict().AddServer().AddEphemeralSigningKey()' to use an ephemeral key.")
                .ToString(), exception.Message);
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIddictServerBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddAuthentication();
                services.AddOptions();
                services.AddDistributedMemoryCache();

                services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        options.SetDefaultApplicationEntity<OpenIddictApplication>()
                               .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                               .SetDefaultScopeEntity<OpenIddictScope>()
                               .SetDefaultTokenEntity<OpenIddictToken>();
                    })

                    .AddServer(options => configuration?.Invoke(options));
            });

            builder.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(context => context.ChallengeAsync(OpenIddictServerDefaults.AuthenticationScheme));
            });

            return new TestServer(builder);
        }

        public class OpenIddictApplication { }
        public class OpenIddictAuthorization { }
        public class OpenIddictScope { }
        public class OpenIddictToken { }
    }
}
