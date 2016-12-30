using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests {
    public partial class OpenIddictProviderTests {
        [Fact]
        public async Task SerializeAuthorizationCode_AuthorizationCodeIsAutomaticallyPersisted() {
            // Arrange
            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.HasRedirectUriAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_RefreshTokenIsAutomaticallyPersisted() {
            // Arrange
            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken, It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
