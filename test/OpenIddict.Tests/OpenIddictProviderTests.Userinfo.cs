using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Moq;
using Xunit;

namespace OpenIddict.Tests {
    public partial class OpenIddictProviderTests {
        [Fact]
        public async Task HandleUserinfoRequest_RequestIsHandledByUserCode() {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder => {
                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(UserinfoEndpoint, new OpenIdConnectRequest {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response[OpenIdConnectConstants.Claims.Subject]);

            format.Verify(mock => mock.Unprotect("SlAV32hkKG"), Times.Once());
        }
    }
}
