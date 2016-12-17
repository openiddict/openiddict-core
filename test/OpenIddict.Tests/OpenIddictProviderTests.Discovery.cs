using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using OpenIddict.Core;
using Xunit;

namespace OpenIddict.Tests {
    public partial class OpenIddictProviderTests {
        [Fact]
        public async Task HandleConfigurationRequest_PlainCodeChallengeMethodIsNotReturned() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.DoesNotContain(
                OpenIdConnectConstants.CodeChallengeMethods.Plain,
                response[OpenIdConnectConstants.Metadata.CodeChallengeMethodsSupported].Values<string>());
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Password)]
        [InlineData(OpenIdConnectConstants.GrantTypes.RefreshToken)]
        public async Task HandleConfigurationRequest_EnabledFlowsAreReturned(string flow) {
            // Arrange
            var server = CreateAuthorizationServer(builder => {
                builder.Configure(options => {
                    options.GrantTypes.Clear();
                    options.GrantTypes.Add(flow);
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);
            var types = response[OpenIdConnectConstants.Metadata.GrantTypesSupported].Values<string>();

            // Assert
            Assert.Equal(1, types.Count());
            Assert.Contains(flow, types);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.Scopes.Profile)]
        [InlineData(OpenIdConnectConstants.Scopes.Email)]
        [InlineData(OpenIdConnectConstants.Scopes.Phone)]
        [InlineData(OpenIddictConstants.Scopes.Roles)]
        public async Task HandleConfigurationRequest_StandardScopesAreExposed(string scope) {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Contains(scope, response[OpenIdConnectConstants.Metadata.ScopesSupported].Values<string>());
        }

        [Fact]
        public async Task HandleConfigurationRequest_OfflineAccessScopeIsReturnedWhenRefreshTokenFlowIsEnabled() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.Contains(OpenIdConnectConstants.Scopes.OfflineAccess,
                response[OpenIdConnectConstants.Metadata.ScopesSupported].Values<string>());
        }

        [Fact]
        public async Task HandleConfigurationRequest_OfflineAccessScopeIsReturnedWhenRefreshTokenFlowIsDisabled() {
            // Arrange
            var server = CreateAuthorizationServer(builder => {
                builder.Configure(options => {
                    // Note: at least one flow must be enabled.
                    options.GrantTypes.Clear();
                    options.GrantTypes.Add(OpenIdConnectConstants.GrantTypes.AuthorizationCode);
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(ConfigurationEndpoint);

            // Assert
            Assert.DoesNotContain(OpenIdConnectConstants.Scopes.OfflineAccess,
                response[OpenIdConnectConstants.Metadata.ScopesSupported].Values<string>());
        }
    }
}
