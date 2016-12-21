using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests {
    public partial class OpenIddictProviderTests {
        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Password)]
        [InlineData(OpenIdConnectConstants.GrantTypes.RefreshToken)]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenFlowIsNotEnabled(string flow) {
            // Arrange
            var server = CreateAuthorizationServer(builder => {
                builder.Configure(options => options.GrantTypes.Remove(flow));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = flow,
                Username = "johndoe",
                Password = "A3ddj3w",
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedGrantType, response.Error);
            Assert.Equal("The specified grant_type is not supported by this authorization server.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled() {
            // Arrange
            var server = CreateAuthorizationServer(builder => {
                builder.Configure(options => options.GrantTypes.Remove(OpenIdConnectConstants.GrantTypes.RefreshToken));
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
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'offline_access' scope is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientCredentialsRequestWithOfflineAccessScopeIsRejected() {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials,
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'offline_access' scope is not allowed when using grant_type=client_credentials.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("client_id", "")]
        [InlineData("", "client_secret")]
        public async Task ValidateTokenRequest_ClientCredentialsRequestIsRejectedWhenCredentialsAreMissing(string identifier, string secret) {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = identifier,
                ClientSecret = secret,
                GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Client applications must be authenticated to use the client credentials grant.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithoutClientIdIsRejectedWhenClientIdentificationIsRequired() {
            // Arrange
            var server = CreateAuthorizationServer(builder => builder.RequireClientIdentification());

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = null,
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter was missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenClientCannotBeFound() {
            // Arrange
            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(null);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Application not found in the database: ensure that your client_id is correct.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientCredentialsRequestFromPublicClientIsRejected() {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("Public clients are not allowed to use the client credentials grant.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretCannotBeUsedByPublicClients() {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Public clients are not allowed to send a client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretIsRequiredForConfidentialClients() {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = null,
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Missing credentials: ensure that you specified a client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenClientCredentialsAreInvalid() {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance => {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                instance.Setup(mock => mock.ValidateSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Invalid credentials: ensure that you specified a correct client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationCodeIsExpired() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetTicketId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(null);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenRefreshTokenIsExpired() {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTicketId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(null);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_AuthorizationCodeIsAutomaticallyRevoked() {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetTicketId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode
            });

            // Assert
            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RefreshTokenIsAutomaticallyRevokedWhenSlidingExpirationIsEnabled() {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTicketId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIdConnectConstants.GrantTypes.Password)]
        [InlineData(OpenIdConnectConstants.GrantTypes.RefreshToken)]
        [InlineData("urn:ietf:params:oauth:grant-type:custom_grant")]
        public async Task HandleTokenRequest_RequestsAreNotHandledLocally(string flow) {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(ClaimTypes.NameIdentifier, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTicketId("60FFF7EA-F98E-437B-937E-5073CC313103");

            switch (flow) {
                case OpenIdConnectConstants.GrantTypes.AuthorizationCode:
                    ticket.SetUsage(OpenIdConnectConstants.Usages.AuthorizationCode);
                    ticket.SetPresenters("Fabrikam");
                    break;

                case OpenIdConnectConstants.GrantTypes.RefreshToken:
                    ticket.SetUsage(OpenIdConnectConstants.Usages.RefreshToken);
                    break;
            }

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance => {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            });

            var server = CreateAuthorizationServer(builder => {
                builder.Services.AddSingleton(CreateApplicationManager(instance => {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                    instance.Setup(mock => mock.ValidateSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Code = "8xLOxBtZp8",
                GrantType = flow,
                RefreshToken = "8xLOxBtZp8",
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }
    }
}
