using System;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
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
        public async Task SerializeAccessToken_AccessTokenIsNotPersistedWhenReferenceTokensAreDisabled()
        {
            // Arrange
            var manager = CreateTokenManager();

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RevocationEndpointPath = PathString.Empty);
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
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AccessToken),
                It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task SerializeAccessToken_ReferenceAccessTokenIsCorrectlyPersisted()
        {
            // Arrange
            var token = new OpenIddictToken
            {
                CreationDate = new DateTimeOffset(2017, 01, 02, 00, 00, 00, TimeSpan.Zero),
                ExpirationDate = new DateTimeOffset(2017, 01, 01, 00, 00, 00, TimeSpan.Zero)
            };

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseReferenceTokens();

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow == token.CreationDate.Value);
                    options.AccessTokenLifetime = token.ExpirationDate.Value - token.CreationDate.Value;
                });
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
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.Ciphertext != null &&
                    descriptor.Hash != null &&
                    descriptor.ExpirationDate == token.ExpirationDate &&
                    descriptor.CreationDate == token.CreationDate &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AccessToken),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAccessToken_ClientApplicationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
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

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                builder.Services.AddSingleton(manager);

                builder.UseReferenceTokens();
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
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.ApplicationId == "3E228451-1555-46F7-A471-951EFBA23A56" &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AccessToken),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAccessToken_AuthorizationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    instance.Setup(mock => mock.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(new OpenIddictAuthorization());
                }));

                builder.Services.AddSingleton(manager);

                builder.UseReferenceTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess,
                ["attach-authorization"] = true
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.AuthorizationId == "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70" &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AccessToken),
                It.IsAny<CancellationToken>()), Times.Once());
        }

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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.IsAny<OpenIddictTokenDescriptor>(),
                It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_AuthorizationCodeIsCorrectlyPersisted()
        {
            // Arrange
            var token = new OpenIddictToken
            {
                CreationDate = new DateTimeOffset(2017, 01, 01, 00, 00, 00, TimeSpan.Zero),
                ExpirationDate = new DateTimeOffset(2017, 01, 02, 00, 00, 00, TimeSpan.Zero)
            };

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
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

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow == token.CreationDate.Value);
                    options.AuthorizationCodeLifetime = token.ExpirationDate.Value - token.CreationDate.Value;
                });
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.Ciphertext == null &&
                    descriptor.Hash == null &&
                    descriptor.ExpirationDate == token.ExpirationDate &&
                    descriptor.CreationDate == token.CreationDate &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AuthorizationCode),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_ReferenceAuthorizationCodeIsCorrectlyPersisted()
        {
            // Arrange
            var token = new OpenIddictToken
            {
                CreationDate = new DateTimeOffset(2017, 01, 01, 00, 00, 00, TimeSpan.Zero),
                ExpirationDate = new DateTimeOffset(2017, 01, 02, 00, 00, 00, TimeSpan.Zero)
            };

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
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

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                builder.Services.AddSingleton(manager);

                builder.UseReferenceTokens();

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow == token.CreationDate.Value);
                    options.AuthorizationCodeLifetime = token.ExpirationDate.Value - token.CreationDate.Value;
                });
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.Ciphertext != null &&
                    descriptor.Hash != null &&
                    descriptor.ExpirationDate == token.ExpirationDate &&
                    descriptor.CreationDate == token.CreationDate &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AuthorizationCode),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_ClientApplicationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.ApplicationId == "3E228451-1555-46F7-A471-951EFBA23A56" &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AuthorizationCode),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_AuthorizationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
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
                ["attach-authorization"] = true
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.ApplicationId == "3E228451-1555-46F7-A471-951EFBA23A56" &&
                    descriptor.AuthorizationId == "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70" &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.AuthorizationCode),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeAuthorizationCode_AdHocAuthorizationIsAutomaticallyCreated()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateAuthorizationManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
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

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                            .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictAuthorizationDescriptor>(descriptor =>
                    descriptor.ApplicationId == "3E228451-1555-46F7-A471-951EFBA23A56" &&
                    descriptor.Subject == "Bob le Magnifique"),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_ExtendsLifetimeWhenRollingTokensAreDisabled()
        {
            // Arrange
            var token = new OpenIddictToken
            {
                CreationDate = new DateTimeOffset(2017, 01, 01, 00, 00, 00, TimeSpan.Zero),
                ExpirationDate = new DateTimeOffset(2017, 01, 10, 00, 00, 00, TimeSpan.Zero)
            };

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByHashAsync("d80c119138b3aaeefce94093032c0204c547dc27cc5fe97f32933becd48b7bf5", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseReferenceTokens();

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow ==
                        new DateTimeOffset(2017, 01, 05, 00, 00, 00, TimeSpan.Zero));
                    options.RefreshTokenLifetime = TimeSpan.FromDays(10);
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "3E228451-1555-46F7-A471-951EFBA23A56"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.ExtendAsync(token,
                new DateTimeOffset(2017, 01, 15, 00, 00, 00, TimeSpan.Zero),
                It.IsAny<CancellationToken>()), Times.Never());
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.IsAny<OpenIddictTokenDescriptor>(),
                It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task SerializeRefreshToken_RefreshTokenIsCorrectlyPersisted()
        {
            // Arrange
            var token = new OpenIddictToken
            {
                CreationDate = new DateTimeOffset(2017, 01, 01, 00, 00, 00, TimeSpan.Zero),
                ExpirationDate = new DateTimeOffset(2017, 01, 02, 00, 00, 00, TimeSpan.Zero)
            };

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow == token.CreationDate.Value);
                    options.RefreshTokenLifetime = token.ExpirationDate.Value - token.CreationDate.Value;
                });
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.Ciphertext == null &&
                    descriptor.Hash == null &&
                    descriptor.ExpirationDate == token.ExpirationDate &&
                    descriptor.CreationDate == token.CreationDate &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.RefreshToken),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_ReferenceRefreshTokenIsCorrectlyPersisted()
        {
            // Arrange
            var token = new OpenIddictToken
            {
                CreationDate = new DateTimeOffset(2017, 01, 01, 00, 00, 00, TimeSpan.Zero),
                ExpirationDate = new DateTimeOffset(2017, 01, 02, 00, 00, 00, TimeSpan.Zero)
            };

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseReferenceTokens();

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow == token.CreationDate.Value);
                    options.RefreshTokenLifetime = token.ExpirationDate.Value - token.CreationDate.Value;
                });
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.Ciphertext != null &&
                    descriptor.Hash != null &&
                    descriptor.ExpirationDate == token.ExpirationDate &&
                    descriptor.CreationDate == token.CreationDate &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.RefreshToken),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_ClientApplicationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
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

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.ApplicationId == "3E228451-1555-46F7-A471-951EFBA23A56" &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.RefreshToken),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task SerializeRefreshToken_AuthorizationIsAutomaticallyAttached()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
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
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess,
                ["attach-authorization"] = true
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(
                It.Is<OpenIddictTokenDescriptor>(descriptor =>
                    descriptor.AuthorizationId == "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70" &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIdConnectConstants.TokenTypeHints.RefreshToken),
                It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
