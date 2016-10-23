using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests.Infrastructure {
    public partial class OpenIddictProviderTests {
        [Theory]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.AccessToken)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.IdToken)]
        public async Task ValidateRevocationRequest_UnknownTokenTokenHintIsRejected(string hint) {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "SlAV32hkKG",
                TokenTypeHint = hint
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("Only authorization codes and refresh tokens can be revoked. When specifying a token_type_hint " +
                         "parameter, its value must be equal to 'authorization_code' or 'refresh_token'.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestWithoutClientIdIsRejectedWhenClientIdentificationIsRequired() {
            // Arrange
            var server = CreateAuthorizationServer(builder => builder.RequireClientIdentification());

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter was missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestIsRejectedWhenClientCannotBeFound() {
            // Arrange
            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam"))
                    .ReturnsAsync(null);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Application not found in the database: ensure that your client_id is correct.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam"), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_ClientSecretCannotBeUsedByPublicClients() {
            // Arrange
            var application = Mock.Of<object>();

            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam"))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Public clients are not allowed to send a client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam"), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_ClientSecretIsRequiredForConfidentialClients() {
            // Arrange
            var application = Mock.Of<object>();

            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam"))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = null,
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Missing credentials: ensure that you specified a client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam"), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestIsRejectedWhenClientCredentialsAreInvalid() {
            // Arrange
            var application = Mock.Of<object>();

            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam"))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                instance.Setup(mock => mock.ValidateSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw"))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Invalid credentials: ensure that you specified a correct client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam"), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw"), Times.Once());
        }

        [Fact]
        public async Task HandleRevocationRequest_RequestIsRejectedWhenTokenIsAnAccessToken() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTicketId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetUsage(OpenIdConnectConstants.Usages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder => {
                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("Only authorization codes and refresh tokens can be revoked.", response.ErrorDescription);

            format.Verify(mock => mock.Unprotect("SlAV32hkKG"), Times.Once());
        }

        [Fact]
        public async Task HandleRevocationRequest_RequestIsNotRejectedWhenTokenIsAnIdentityToken() {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Usage, OpenIdConnectConstants.Usages.IdentityToken);

            var handler = new Mock<JwtSecurityTokenHandler>();

            handler.Setup(mock => mock.CanReadToken("SlAV32hkKG"))
                .Returns(true);

            handler.As<ISecurityTokenValidator>()
                .Setup(mock => mock.ValidateToken("SlAV32hkKG", It.IsAny<TokenValidationParameters>(), out token))
                .Returns(new ClaimsPrincipal(identity));

            var server = CreateAuthorizationServer(builder => {
                builder.Configure(options => options.IdentityTokenHandler = handler.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("Only authorization codes and refresh tokens can be revoked.", response.ErrorDescription);

            handler.As<ISecurityTokenValidator>()
                .Verify(mock => mock.CanReadToken("SlAV32hkKG"), Times.Once());

            handler.As<ISecurityTokenValidator>()
                .Verify(mock => mock.ValidateToken("SlAV32hkKG", It.IsAny<TokenValidationParameters>(), out token), Times.Once());
        }

        [Fact]
        public async Task HandleRevocationRequest_TokenIsNotRevokedWhenItIsAlreadyInvalid() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTicketId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56"))
                    .ReturnsAsync(null);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(0, response.Count());

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56"), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(It.IsAny<object>()), Times.Never());
        }

        [Fact]
        public async Task HandleRevocationRequest_TokenIsSuccessfullyRevoked() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTicketId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var token = Mock.Of<object>();

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56"))
                    .ReturnsAsync(token);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(0, response.Count());

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56"), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(token), Times.Once());
        }
    }
}
