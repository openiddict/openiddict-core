using System.IO;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Xunit;

namespace OpenIddict.Core.Tests.Infrastructure {
    public partial class OpenIddictProviderTests {
        [Fact]
        public async Task SerializeAuthorizationCode_AuthorizationCodeIsAutomaticallyPersisted() {
            // Arrange
            var request = new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            };

            var stream = new MemoryStream();
            using (var writer = new BsonWriter(stream)) {
                writer.CloseOutput = false;

                var serializer = JsonSerializer.CreateDefault();
                serializer.Serialize(writer, request);
            }

            var cache = new Mock<IDistributedCache>();

            cache.Setup(mock => mock.GetAsync(OpenIddictConstants.Environment.AuthorizationRequest +
                                              "b2ee7815-5579-4ff7-86b0-ba671b939d96"))
                .ReturnsAsync(stream.ToArray());

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = Mock.Of<object>();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam"))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path"))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);

                builder.Services.AddSingleton(cache.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest {
                RequestId = "b2ee7815-5579-4ff7-86b0-ba671b939d96"
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_RefreshTokenIsAutomaticallyPersisted() {
            // Arrange
            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken))
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken), Times.Once());
        }
    }
}
