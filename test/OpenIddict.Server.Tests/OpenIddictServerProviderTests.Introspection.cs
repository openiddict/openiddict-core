/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public partial class OpenIddictServerProviderTests
    {
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
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' and/or 'client_secret' parameters are missing.", response.ErrorDescription);
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
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The specified 'client_id' parameter is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Endpoints.Introspection, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreEndpointPermissions = false);
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
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the introspection endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Endpoints.Introspection, It.IsAny<CancellationToken>()), Times.Once());
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
                    .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
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
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("This client application is not allowed to use the introspection endpoint.", response.ErrorDescription);

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
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidClient, response.Error);
            Assert.Equal("The specified client credentials are invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.TokenUsages.AuthorizationCode)]
        [InlineData(OpenIdConnectConstants.TokenUsages.IdToken)]
        [InlineData(OpenIdConnectConstants.TokenUsages.RefreshToken)]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenTokenIsNotAnAccessToken(string type)
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(type);

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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

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
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenAudienceIsMissing()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

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
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenClientIsNotAValidAudience()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetAudiences("Contoso");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

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
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenReferenceTokenIsUnknown()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(manager);

                builder.UseReferenceTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);


            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_AuthorizationIsIgnoredWhenAuthorizationStorageIsDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetAudiences("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIdConnectConstants.TokenUsages.AccessToken));

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("2YotnFZFEjr1zCsicMWpAA"));

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.DisableAuthorizationStorage();
                builder.UseReferenceTokens();

                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenAuthorizationCannotBeFound()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetAudiences("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIdConnectConstants.TokenUsages.AccessToken));

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("2YotnFZFEjr1zCsicMWpAA"));

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AccessTokenFormat = format.Object);

                builder.UseReferenceTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenAuthorizationIsInvalid()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetAudiences("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(OpenIdConnectConstants.TokenUsages.AccessToken));

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                    instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("2YotnFZFEjr1zCsicMWpAA"));

                    instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    instance.Setup(mock => mock.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AccessTokenFormat = format.Object);

                builder.UseReferenceTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenReferenceTokenIsInvalid()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetAudiences("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AccessToken);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("2YotnFZFEjr1zCsicMWpAA"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(OpenIdConnectConstants.TokenUsages.AccessToken));

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));

                instance.Setup(mock => mock.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("2YotnFZFEjr1zCsicMWpAA"));

                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Confidential));

                    instance.Setup(mock => mock.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.AccessTokenFormat = format.Object);

                builder.UseReferenceTokens();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(IntrospectionEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Single(response.GetParameters());
            Assert.False((bool) response[OpenIddictConstants.Claims.Active]);

            Mock.Get(manager).Verify(mock => mock.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }
    }
}
