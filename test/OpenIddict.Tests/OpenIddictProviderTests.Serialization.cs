using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
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
        public async Task SerializeAuthorizationCode_AuthorizationCodeIsNotPersistedWhenRevocationIsDisabled()
        {
            // Arrange
            var manager = CreateTokenManager();

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.HasRedirectUriAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RevocationEndpointPath = PathString.Empty);

                builder.DisableTokenRevocation();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, "Bob le Magnifique", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_AuthorizationCodeIsCorrectlyPersisted()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, "Bob le Magnifique", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.HasRedirectUriAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, "Bob le Magnifique", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_ClientApplicationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, "Bob le Magnifique", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                instance.Setup(mock => mock.SetClientAsync(token, "3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .Returns(Task.FromResult(0));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.HasRedirectUriAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.SetClientAsync(token, "3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_AuthorizationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.AuthorizationCode, "Bob le Magnifique", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                instance.Setup(mock => mock.SetClientAsync(token, "3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .Returns(Task.FromResult(0));

                instance.Setup(mock => mock.SetAuthorizationAsync(token, "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                    .Returns(Task.FromResult(0));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.HasRedirectUriAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    instance.Setup(mock => mock.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new OpenIddictAuthorization());
                }));

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.SetAuthorizationAsync(token, "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_RefreshTokenIsNotPersistedWhenRevocationIsDisabled()
        {
            // Arrange
            var manager = CreateTokenManager();

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RevocationEndpointPath = PathString.Empty);

                builder.DisableTokenRevocation();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken, "Bob le Magnifique", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task SerializeRefreshToken_RefreshTokenIsCorrectlyPersisted()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken, "Bob le Magnifique", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken, "Bob le Magnifique", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_ClientApplicationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken, "Bob le Magnifique", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                instance.Setup(mock => mock.SetClientAsync(token, "3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .Returns(Task.FromResult(0));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.SetClientAsync(token, "3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_AuthorizationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(OpenIdConnectConstants.TokenTypeHints.RefreshToken, "Bob le Magnifique", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                instance.Setup(mock => mock.SetAuthorizationAsync(token, "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                    .Returns(Task.FromResult(0));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    instance.Setup(mock => mock.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new OpenIddictAuthorization());
                }));

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.SetAuthorizationAsync(token, "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
