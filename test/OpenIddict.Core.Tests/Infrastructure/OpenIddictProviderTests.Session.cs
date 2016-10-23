using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests.Infrastructure {
    public partial class OpenIddictProviderTests {
        [Fact]
        public async Task ExtractLogoutRequest_InvalidRequestIdParameterIsRejected() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Invalid request: timeout expired.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateLogoutRequest_RequestIsRejectedWhenRedirectUriIsInvalid() {
            // Arrange
            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path"))
                    .ReturnsAsync(null);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Invalid post_logout_redirect_uri.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path"), Times.Once());
        }

        [Fact]
        public async Task HandleLogoutRequest_RequestIsPersistedInDistributedCache() {
            // Arrange
            var cache = new Mock<IDistributedCache>();

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = Mock.Of<object>();

                    instance.Setup(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path"))
                        .ReturnsAsync(application);
                }));

                builder.Services.AddSingleton(cache.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            var identifier = (string) response[OpenIdConnectConstants.Parameters.RequestId];

            // Assert
            Assert.Equal(1, response.Count());
            Assert.NotNull(identifier);

            cache.Verify(mock => mock.SetAsync(
                OpenIddictConstants.Environment.LogoutRequest + identifier,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>()), Times.Once());
        }

        [Fact]
        public async Task ApplyLogoutResponse_ErroredRequestIsNotHandledLocallyWhenStatusCodeMiddlewareIsEnabled() {
            // Arrange
            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    instance.Setup(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path"))
                        .ReturnsAsync(null);
                }));

                builder.EnableAuthorizationEndpoint("/logout-status-code-middleware");
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync("/logout-status-code-middleware", new OpenIdConnectRequest {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, (string) response["error_custom"]);
        }
    }
}
