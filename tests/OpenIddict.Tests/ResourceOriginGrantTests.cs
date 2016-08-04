using System.Net;
using Xunit;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using OpenIddict.Tests.Infrastructure;

namespace OpenIddict.Tests
{
    public class ResourceOriginGrantTests : BaseHostedTests
    {
        [Fact]
        public Task Should_Return200Ok_When_SendingRopcRequest()
        {
            return UseTestHost(async client =>
            {
                // Arrange
                var request = new OpenIdConnectRequestBuilder()
                    .WithClientId("myClient")
                    .WithClientSecret("secret_secret_secret")
                    .WithUsername("Me")
                    .WithPassword("Pwd")
                    .WithGrantType("password")
                    .BuildRequestMessage();

                // Act
                var httpResponse = await client.SendAsync(request);

                // Assert
                var iodcResponse = await httpResponse.ToOpenIdConnectResponseAsync();

                Assert.Equal(HttpStatusCode.OK, httpResponse.StatusCode);
                Assert.Equal(OpenIdConnectConstants.TokenTypes.Bearer, iodcResponse.TokenType);
                Assert.NotNull(iodcResponse.AccessToken);
            });
        }

        [Fact]
        public Task Should_Return200Ok_When_SendingRopcRequestWithoutClientId_ConfidentialClient()
        {
            return UseTestHost(async client =>
            {
                // Arrange
                var request = new OpenIdConnectRequestBuilder()
                    .WithClientSecret("secret_secret_secret")
                    .WithUsername("Me")
                    .WithPassword("Pwd")
                    .WithGrantType("password")
                    .BuildRequestMessage();

                // Act
                var httpResponse = await client.SendAsync(request);

                // Assert
                var iodcResponse = await httpResponse.ToOpenIdConnectResponseAsync();

                Assert.Equal(HttpStatusCode.OK, httpResponse.StatusCode);
                Assert.Equal(OpenIdConnectConstants.TokenTypes.Bearer, iodcResponse.TokenType);
                Assert.NotNull(iodcResponse.AccessToken);
            });
        }

        [Fact]
        public Task Should_Return400_When_SendingRopcRequestWithInvalidClientId()
        {
            return UseTestHost(async client =>
            {
                // Arrange
                var request = new OpenIdConnectRequestBuilder()
                    .WithClientId("myClient2")
                    .WithClientSecret("secret_secret_secret")
                    .WithUsername("Me")
                    .WithPassword("Pwd")
                    .WithGrantType("password")
                    .BuildRequestMessage();

                // Act
                var httpResponse = await client.SendAsync(request);

                // Assert
                var iodcResponse = await httpResponse.ToOpenIdConnectResponseAsync();

                Assert.Equal(HttpStatusCode.BadRequest, httpResponse.StatusCode);
                Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, iodcResponse.Error);
                Assert.NotNull(iodcResponse.ErrorDescription);
            });
        }

        [Fact]
        public Task Should_Return400_When_SendingRopcRequestWithInvalidUsername()
        {
            return UseTestHost(async client =>
            {
                // Arrange
                var request = new OpenIdConnectRequestBuilder()
                    .WithClientId("myClient")
                    .WithClientSecret("secret_secret_secret")
                    .WithUsername("MeMe")
                    .WithPassword("Pwd")
                    .WithGrantType("password")
                    .BuildRequestMessage();

                // Act
                var httpResponse = await client.SendAsync(request);

                // Assert
                var iodcResponse = await httpResponse.ToOpenIdConnectResponseAsync();

                Assert.Equal(HttpStatusCode.BadRequest, httpResponse.StatusCode);
                Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, iodcResponse.Error);
                Assert.NotNull(iodcResponse.ErrorDescription);
            });
        }

        [Fact]
        public Task Should_Return400_When_SendingRopcRequestWithInvalidPassword()
        {
            return UseTestHost(async client =>
            {
                // Arrange
                var request = new OpenIdConnectRequestBuilder()
                    .WithClientId("myClient")
                    .WithClientSecret("secret_secret_secret")
                    .WithUsername("Me")
                    .WithPassword("PwdPwd")
                    .WithGrantType("password")
                    .BuildRequestMessage();

                // Act
                var httpResponse = await client.SendAsync(request);

                // Assert
                var iodcResponse = await httpResponse.ToOpenIdConnectResponseAsync();

                Assert.Equal(HttpStatusCode.BadRequest, httpResponse.StatusCode);
                Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, iodcResponse.Error);
                Assert.NotNull(iodcResponse.ErrorDescription);
            });
        }
    }
}
