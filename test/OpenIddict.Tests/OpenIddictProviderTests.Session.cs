using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests
{
    public partial class OpenIddictProviderTests
    {
        [Fact]
        public async Task ExtractLogoutRequest_RequestIdParameterIsRejectedWhenRequestCachingIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The request_id parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractLogoutRequest_InvalidRequestIdParameterIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddDistributedMemoryCache();

                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Invalid request: timeout expired.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateLogoutRequest_RequestIsRejectedWhenRedirectUriIsInvalid()
        {
            // Arrange
            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Invalid post_logout_redirect_uri.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleLogoutRequest_RequestIsPersistedInDistributedCache()
        {
            // Arrange
            var cache = new Mock<IDistributedCache>();

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);
                }));

                builder.Services.AddSingleton(cache.Object);

                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            var identifier = (string) response[OpenIdConnectConstants.Parameters.RequestId];

            // Assert
            Assert.Equal(1, response.GetParameters().Count());
            Assert.NotNull(identifier);

            cache.Verify(mock => mock.SetAsync(
                OpenIddictConstants.Environment.LogoutRequest + identifier,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleLogoutRequest_RequestsAreNotHandledLocally()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path",
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("af0ifjsldkj", response.State);
        }

        [Fact]
        public async Task ApplyLogoutResponse_ErroredRequestIsNotHandledLocallyWhenStatusCodeMiddlewareIsEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    instance.Setup(mock => mock.FindByLogoutRedirectUri("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(value: null);
                }));

                builder.EnableAuthorizationEndpoint("/logout-status-code-middleware");
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync("/logout-status-code-middleware", new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, (string) response["error_custom"]);
        }
    }
}
