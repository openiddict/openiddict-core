using System;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace OpenIddict.Tests
{
    public class OpenIddictInitializerTests
    {
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
        public async Task PostConfigure_ThrowsAnExceptionWhenNoFlowIsEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => { });
            });

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
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit)]
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

            Assert.Equal("The authorization endpoint must be enabled to use " +
                         "the authorization code and implicit flows.", exception.Message);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Password)]
        [InlineData(OpenIdConnectConstants.GrantTypes.RefreshToken)]
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
        public async Task PostConfigure_ThrowsAnExceptionWhenTokenRevocationIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .EnableRevocationEndpoint("/connect/revocation")
                       .AllowImplicitFlow()
                       .DisableTokenRevocation();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The revocation endpoint cannot be enabled when token revocation is disabled.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenUsingReferenceTokensWithTokenRevocationDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/connect/authorize")
                       .AllowImplicitFlow()
                       .DisableTokenRevocation()
                       .UseReferenceTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("Reference tokens cannot be used when disabling token revocation.", exception.Message);
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

            Assert.Equal(
                "At least one signing key must be registered when using JWT as the access token format. " +
                "Consider registering a X.509 certificate using 'services.AddOpenIddict().AddSigningCertificate()' " +
                "or 'services.AddOpenIddict().AddDevelopmentSigningCertificate()' or call " +
                "'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.", exception.Message);
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

            Assert.Equal(
                "At least one asymmetric signing key must be registered when enabling the implicit flow. " +
                "Consider registering a X.509 certificate using 'services.AddOpenIddict().AddSigningCertificate()' " +
                "or 'services.AddOpenIddict().AddDevelopmentSigningCertificate()' or call " +
                "'services.AddOpenIddict().AddEphemeralSigningKey()' to use an ephemeral key.", exception.Message);
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIddictBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddAuthentication();
                services.AddOptions();
                services.AddDistributedMemoryCache();

                services.AddOpenIddict(options => configuration?.Invoke(options));
            });

            builder.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(context => context.ChallengeAsync(OpenIdConnectServerDefaults.AuthenticationScheme));
            });

            return new TestServer(builder);
        }
    }
}
