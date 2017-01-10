using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Xunit;

namespace OpenIddict.Tests {
    public partial class OpenIddictProviderTests {
        [Fact]
        public async Task ExtractUserinfoRequest_RequestIsHandledByUserCode() {
            // Arrange
            var server = CreateAuthorizationServer();
            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("SlAV32hkKG", (string) response[OpenIdConnectConstants.Parameters.AccessToken]);
            Assert.Equal("Bob le Bricoleur", (string) response[OpenIdConnectConstants.Claims.Subject]);
        }
    }
}
