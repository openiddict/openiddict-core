/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public partial class OpenIddictServerProviderTests
    {
        [Theory]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIddictConstants.GrantTypes.Password)]
        [InlineData(OpenIddictConstants.GrantTypes.RefreshToken)]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenFlowIsNotEnabled(string flow)
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.GrantTypes.Remove(flow));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = flow,
                Username = "johndoe",
                Password = "A3ddj3w",
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnsupportedGrantType, response.Error);
            Assert.Equal("The specified 'grant_type' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.GrantTypes.Remove(OpenIddictConstants.GrantTypes.RefreshToken));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIddictConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'offline_access' scope is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeRequestIsRejectedWhenRedirectUriIsMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = null
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'redirect_uri' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeRequestIsRejectedWhenCodeVerifierIsMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder => builder.RequireProofKeyForCodeExchange());

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                CodeVerifier = null,
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'code_verifier' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenUnregisteredScopeIsSpecified()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateScopeManager(instance =>
                {
                    instance.Setup(mock => mock.FindByNamesAsync(
                        It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "unregistered_scope"),
                        It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ImmutableArray.Create<OpenIddictScope>());
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "unregistered_scope"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidScope, response.Error);
            Assert.Equal("The specified 'scope' parameter is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsValidatedWhenScopeRegisteredInOptionsIsSpecified()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.RegisterScopes("registered_scope");
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "registered_scope"
            });

            // Assert
            Assert.Null(response.Error);
            Assert.Null(response.ErrorDescription);
            Assert.Null(response.ErrorUri);
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsValidatedWhenRegisteredScopeIsSpecified()
        {
            // Arrange
            var scope = new OpenIddictScope();

            var manager = CreateScopeManager(instance =>
            {
                instance.Setup(mock => mock.FindByNamesAsync(
                    It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "scope_registered_in_database"),
                    It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableArray.Create(scope));

                instance.Setup(mock => mock.GetNameAsync(scope, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("scope_registered_in_database"));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.RegisterScopes("scope_registered_in_options");

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "scope_registered_in_database scope_registered_in_options"
            });

            // Assert
            Assert.Null(response.Error);
            Assert.Null(response.ErrorDescription);
            Assert.Null(response.ErrorUri);
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientCredentialsRequestWithOfflineAccessScopeIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.ClientCredentials,
                Scope = OpenIddictConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'offline_access' scope is not valid for the specified 'grant_type' parameter.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("client_id", "")]
        [InlineData("", "client_secret")]
        public async Task ValidateTokenRequest_ClientCredentialsRequestIsRejectedWhenCredentialsAreMissing(string identifier, string secret)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = identifier,
                ClientSecret = secret,
                GrantType = OpenIddictConstants.GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'client_id' and 'client_secret' parameters are " +
                         "required when using the client credentials grant.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithoutClientIdIsRejectedWhenClientIdentificationIsRequired()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.AcceptAnonymousClients = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = null,
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenClientCannotBeFound()
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
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The specified 'client_id' parameter is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Endpoints.Token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreEndpointPermissions = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the token endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Endpoints.Token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenGrantTypePermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.GrantTypes.Password, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreGrantTypePermissions = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the specified grant type.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.GrantTypes.Password, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.GrantTypes.Password, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreGrantTypePermissions = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIddictConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The client application is not allowed to use the 'offline_access' scope.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientCredentialsRequestFromPublicClientIsRejected()
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
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIddictConstants.GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("The specified 'grant_type' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenScopePermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Prefixes.Scope +
                    OpenIddictConstants.Scopes.Profile, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Prefixes.Scope +
                    OpenIddictConstants.Scopes.Email, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
                builder.RegisterScopes(OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile);
                builder.Configure(options => options.IgnoreScopePermissions = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "openid offline_access profile email"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("This client application is not allowed to use the specified scope.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Prefixes.Scope +
                OpenIddictConstants.Scopes.OpenId, It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Prefixes.Scope +
                OpenIddictConstants.Scopes.OfflineAccess, It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Prefixes.Scope +
                OpenIddictConstants.Scopes.Profile, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Prefixes.Scope +
                OpenIddictConstants.Scopes.Email, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretCannotBeUsedByPublicClients()
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
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'client_secret' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretIsRequiredForConfidentialClients()
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
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = null,
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The 'client_secret' parameter required for this client application is missing.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretIsRequiredForHybridClients()
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
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = null,
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The 'client_secret' parameter required for this client application is missing.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenClientCredentialsAreInvalid()
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
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The specified client credentials are invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_AuthorizationCodeRevocationIsIgnoredWhenTokenStorageIsDisabled()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
                builder.Configure(options => options.RevocationEndpointPath = PathString.Empty);

                builder.DisableTokenStorage();
                builder.DisableSlidingExpiration();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleTokenRequest_RefreshTokenRevocationIsIgnoredWhenTokenStorageIsDisabled()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
                builder.Configure(options => options.RevocationEndpointPath = PathString.Empty);

                builder.DisableTokenStorage();
                builder.DisableSlidingExpiration();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationCodeIsUnknown()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenRefreshTokenIsUnknown()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationCodeIsAlreadyRedeemed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenRefreshTokenIsAlreadyRedeemed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103951EFBA23A56"));

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesAuthorizationWhenAuthorizationCodeIsAlreadyRedeemed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);
            ticket.SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ImmutableArray.Create<OpenIddictToken>());
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesAuthorizationWhenRefreshTokenIsAlreadyRedeemed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ImmutableArray.Create<OpenIddictToken>());
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesTokensWhenAuthorizationCodeIsAlreadyRedeemed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);
            ticket.SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var tokens = ImmutableArray.Create(
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken());

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                instance.Setup(mock => mock.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                instance.Setup(mock => mock.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("481FCAC6-06BC-43EE-92DB-37A78AA09B595073CC313103"));

                instance.Setup(mock => mock.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8"));

                instance.Setup(mock => mock.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));

                instance.Setup(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    var authorization = new OpenIddictAuthorization();

                    instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(authorization);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesTokensWhenRefreshTokenIsAlreadyRedeemed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var tokens = ImmutableArray.Create(
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken());

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                instance.Setup(mock => mock.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                instance.Setup(mock => mock.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("481FCAC6-06BC-43EE-92DB-37A78AA09B595073CC313103"));

                instance.Setup(mock => mock.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8"));

                instance.Setup(mock => mock.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));

                instance.Setup(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    var authorization = new OpenIddictAuthorization();

                    instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(authorization);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationCodeIsInvalid()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenRefreshTokenIsInvalid()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103951EFBA23A56"));

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_AuthorizationAssociatedWithCodeIsIgnoredWhenAuthorizationStorageIsDisabled()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.DisableAuthorizationStorage();

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleTokenRequest_AuthorizationAssociatedWithRefreshTokenIsIgnoredWhenAuthorizationStorageIsDisabled()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.DisableAuthorizationStorage();

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithAuthorizationCodeCannotBeFound()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithAuthorizationCodeIsInvalid()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);

                instance.Setup(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIddictConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithRefreshTokenCannotBeFound()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103951EFBA23A56"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithRefreshTokenIsInvalid()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);

                instance.Setup(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103951EFBA23A56"));

                    instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode)]
        [InlineData(OpenIddictConstants.GrantTypes.ClientCredentials)]
        [InlineData(OpenIddictConstants.GrantTypes.Password)]
        [InlineData(OpenIddictConstants.GrantTypes.RefreshToken)]
        [InlineData("urn:ietf:params:oauth:grant-type:custom_grant")]
        public async Task HandleTokenRequest_RequestsAreNotHandledLocally(string flow)
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");

            switch (flow)
            {
                case OpenIddictConstants.GrantTypes.AuthorizationCode:
                    ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);
                    ticket.SetPresenters("Fabrikam");
                    break;

                case OpenIddictConstants.GrantTypes.RefreshToken:
                    ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
                    break;
            }

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103951EFBA23A56"));

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    var authorization = new OpenIddictAuthorization();

                    instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(authorization);

                    instance.Setup(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Code = "8xLOxBtZp8",
                GrantType = flow,
                RedirectUri = "http://www.fabrikam.com/path",
                RefreshToken = "8xLOxBtZp8",
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }
    }
}
