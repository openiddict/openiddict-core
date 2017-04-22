using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
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
        public async Task ExtractIntrospectionRequest_GetRequestsAreRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.GetAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Introspection requests must use HTTP POST.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("client_id", "")]
        [InlineData("", "client_secret")]
        public async Task ValidateIntrospectionRequest_ClientCredentialsRequestIsRejectedWhenCredentialsAreMissing(string identifier, string secret)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = identifier,
                ClientSecret = secret,
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Clients must be authenticated to use the introspection endpoint.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestIsRejectedWhenClientCannotBeFound()
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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Application not found in the database: ensure that your client_id is correct.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestsSentByPublicClientsAreRejected()
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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Public applications are not allowed to use the introspection endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestIsRejectedWhenClientCredentialsAreInvalid()
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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("Invalid credentials: ensure that you specified a correct client_secret.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenClientIsNotAValidAudience()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetAudiences("Contoso");
            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(1, response.GetParameters().Count());
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_AuthorizationCodeRevocationIsIgnoredWhenTokenRevocationIsDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
                builder.Configure(options => options.RevocationEndpointPath = PathString.Empty);

                builder.DisableTokenRevocation();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RefreshTokenRevocationIsIgnoredWhenTokenRevocationIsDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
                builder.Configure(options => options.RevocationEndpointPath = PathString.Empty);

                builder.DisableTokenRevocation();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.True((bool) response[OpenIdConnectConstants.Claims.Active]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenAuthorizationCodeIsRevoked()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
                .Returns(ticket);

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(1, response.GetParameters().Count());
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenRefreshTokenIsRevoked()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
                .Returns(ticket);

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(1, response.GetParameters().Count());
            Assert.False((bool) response[OpenIdConnectConstants.Claims.Active]);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
