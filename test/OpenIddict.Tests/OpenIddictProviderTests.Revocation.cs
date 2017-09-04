using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests
{
    public partial class OpenIddictProviderTests
    {
        [Fact]
        public async Task ValidateRevocationRequest_IdTokenTokenTokenHintIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.IdToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal(
                "Identity tokens cannot be revoked. When specifying a token_type_hint parameter, " +
                "its value must be equal to 'access_token', 'authorization_code' or 'refresh_token'.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateRevocationRequest_AccessTokenTokenTokenHintIsRejectedWhenReferenceTokensAreDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal(
                "Access tokens cannot be revoked. When specifying a token_type_hint parameter, " +
                "its value must be equal to 'authorization_code' or 'refresh_token'.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestWithoutClientIdIsRejectedWhenClientIdentificationIsRequired()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder => builder.RequireClientIdentification());

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter was missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestIsRejectedWhenClientCannotBeFound()
        {
            // Arrange
            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Application not found in the database: ensure that your client_id is correct.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_ClientSecretCannotBeUsedByPublicClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Public clients are not allowed to send a client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_ClientSecretIsRequiredForConfidentialClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = null,
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Missing credentials: ensure that you specified a client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestIsRejectedWhenClientCredentialsAreInvalid()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Invalid credentials: ensure that you specified a correct client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleRevocationRequest_RequestIsRejectedWhenTokenIsAnAccessTokenIfReferenceTokensAreDisabled()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("The specified access token cannot be revoked.", response.ErrorDescription);

            format.Verify(mock => mock.Unprotect("SlAV32hkKG"), Times.Once());
        }

        [Fact]
        public async Task HandleRevocationRequest_RequestIsRejectedWhenTokenIsAnIdentityToken()
        {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.IdToken);

            var handler = new Mock<JwtSecurityTokenHandler>();

            handler.Setup(mock => mock.CanReadToken("SlAV32hkKG"))
                .Returns(true);

            handler.As<ISecurityTokenValidator>()
                .Setup(mock => mock.ValidateToken("SlAV32hkKG", It.IsAny<TokenValidationParameters>(), out token))
                .Returns(new ClaimsPrincipal(identity));

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.IdentityTokenHandler = handler.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("Identity tokens cannot be revoked.", response.ErrorDescription);

            handler.As<ISecurityTokenValidator>()
                .Verify(mock => mock.CanReadToken("SlAV32hkKG"), Times.Once());

            handler.As<ISecurityTokenValidator>()
                .Verify(mock => mock.ValidateToken("SlAV32hkKG", It.IsAny<TokenValidationParameters>(), out token), Times.Once());
        }

        [Fact]
        public async Task HandleRevocationRequest_TokenIsNotRevokedWhenItIsUnknown()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Empty(response.GetParameters());

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(It.IsAny<OpenIddictToken>(), It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleRevocationRequest_TokenIsNotRevokedWhenItIsAlreadyRevoked()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.IsRevokedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Empty(response.GetParameters());

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(It.IsAny<OpenIddictToken>(), It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleRevocationRequest_TokenIsSuccessfullyRevoked()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Empty(response.GetParameters());

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
