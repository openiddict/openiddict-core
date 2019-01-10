/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public partial class OpenIddictServerProviderTests
    {
        [Theory]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.AccessToken)]
        [InlineData(OpenIdConnectConstants.TokenTypeHints.IdToken)]
        public async Task ValidateRevocationRequest_UnsupportedTokenTypeHintIsRejected(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = type
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("The specified 'token_type_hint' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestWithoutClientIdIsRejectedWhenClientIdentificationIsRequired()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.AcceptAnonymousClients = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(RevocationEndpoint, new OpenIdConnectRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = OpenIdConnectConstants.TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter is missing.", response.ErrorDescription);
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
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The specified 'client_id' parameter is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Endpoints.Revocation, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreEndpointPermissions = false);
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
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the revocation endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Endpoints.Revocation, It.IsAny<CancellationToken>()), Times.Once());
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
                    .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
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
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'client_secret' parameter is not valid for this client application.", response.ErrorDescription);

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
                    .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));
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
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The 'client_secret' parameter required for this client application is missing.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateRevocationRequest_ClientSecretIsRequiredForHybridClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Hybrid));
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
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The 'client_secret' parameter required for this client application is missing.", response.ErrorDescription);

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
                    .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

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
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The specified client credentials are invalid.", response.ErrorDescription);

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
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
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
            Assert.Equal(OpenIddictConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("The specified token cannot be revoked.", response.ErrorDescription);

            format.Verify(mock => mock.Unprotect("SlAV32hkKG"), Times.Once());
        }

        [Fact]
        public async Task HandleRevocationRequest_RequestIsRejectedWhenTokenIsAnIdentityToken()
        {
            // Arrange
            var token = Mock.Of<SecurityToken>(mock =>
                mock.ValidFrom == DateTime.UtcNow.AddDays(-1) &&
                mock.ValidTo == DateTime.UtcNow.AddDays(1));

            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.TokenUsage, OpenIdConnectConstants.TokenUsages.IdToken);

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
            Assert.Equal(OpenIddictConstants.Errors.UnsupportedTokenType, response.Error);
            Assert.Equal("The specified token cannot be revoked.", response.ErrorDescription);

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
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

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
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

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

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(It.IsAny<OpenIddictToken>(), It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleRevocationRequest_TokenIsSuccessfullyRevoked()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SlAV32hkKG"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));
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

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
