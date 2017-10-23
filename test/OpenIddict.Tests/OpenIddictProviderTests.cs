/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests
{
    public partial class OpenIddictProviderTests
    {
        public const string AuthorizationEndpoint = "/connect/authorize";
        public const string ConfigurationEndpoint = "/.well-known/openid-configuration";
        public const string IntrospectionEndpoint = "/connect/introspect";
        public const string LogoutEndpoint = "/connect/logout";
        public const string RevocationEndpoint = "/connect/revoke";
        public const string TokenEndpoint = "/connect/token";
        public const string UserinfoEndpoint = "/connect/userinfo";

        [Fact]
        public async Task ProcessChallengeResponse_CustomPublicParametersAreAddedToAuthorizationResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                ["attach-public-parameters"] = true,
                ["deny-authorization"] = true
            });

            // Assert
            Assert.NotEmpty(response.Error);
            Assert.NotEmpty(response.ErrorDescription);
            Assert.True((bool) response["custom_boolean_parameter"]);
            Assert.Equal(42, (long) response["custom_integer_parameter"]);
            Assert.Equal("value", (string) response["custom_string_parameter"]);
        }

        [Fact]
        public async Task ProcessChallengeResponse_CustomPublicParametersAreAddedToTokenResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess,
                ["attach-public-parameters"] = true,
                ["deny-authorization"] = true
            });

            // Assert
            Assert.NotEmpty(response.Error);
            Assert.NotEmpty(response.ErrorDescription);
            Assert.True((bool) response["custom_boolean_parameter"]);
            Assert.Equal(42, (long) response["custom_integer_parameter"]);
            Assert.Equal(new JArray(1, 2, 3), (JArray) response["custom_json_array_parameter"]);
            Assert.Equal(JObject.FromObject(new { Property = "value" }), (JObject) response["custom_json_object_parameter"]);
            Assert.Equal("value", (string) response["custom_string_parameter"]);
        }

        [Fact]
        public async Task ProcessSigninResponse_AuthenticationPropertiesAreAutomaticallyRestored()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);
            ticket.SetProperty("custom_property_in_original_ticket", "original_value");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseRollingTokens();

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                ["do-not-flow-original-properties"] = true
            });

            // Assert
            Assert.NotNull(response.IdToken);
            Assert.NotNull(response.RefreshToken);

            format.Verify(mock => mock.Protect(
                It.Is<AuthenticationTicket>(value =>
                    value.Properties.Items["custom_property_in_original_ticket"] == "original_value" &&
                    value.Properties.Items["custom_property_in_new_ticket"] == "new_value")));
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsIssuedForAuthorizationCodeRequestsWhenRollingTokensAreEnabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("SplxlOBeZQQYbYS6WxSbIA"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
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
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));

                builder.Services.AddSingleton(manager);

                builder.UseRollingTokens();

                builder.Configure(options => options.AuthorizationCodeFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsAlwaysIssuedWhenRollingTokensAreEnabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseRollingTokens();

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsNotIssuedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSigninResponse_AuthorizationCodeIsAutomaticallyRedeemed()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
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
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
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
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
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
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_ReturnsErrorResponseWhenRedeemingAuthorizationCodeFails()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
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
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()))
                    .ThrowsAsync(new Exception());
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
                GrantType = OpenIdConnectConstants.GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsAutomaticallyRedeemedWhenRollingTokensAreEnabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseRollingTokens();

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_ReturnsErrorResponseWhenRedeemingRefreshTokenFails()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()))
                    .ThrowsAsync(new Exception());
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseRollingTokens();

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsNotRedeemedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSigninResponse_PreviousTokensAreAutomaticallyRevokedWhenRollingTokensAreEnabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);
            ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId, "18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var tokens = ImmutableArray.Create(
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken());

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                instance.Setup(mock => mock.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                instance.Setup(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.UseRollingTokens();

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_PreviousTokensAreNotRevokedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);
            ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId, "18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var tokens = ImmutableArray.Create(
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken());

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                instance.Setup(mock => mock.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.RefreshTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSigninResponse_ExtendsLifetimeWhenRollingTokensAreDisabledAndSlidingExpirationEnabled()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow ==
                        new DateTimeOffset(2017, 01, 05, 00, 00, 00, TimeSpan.Zero));
                    options.RefreshTokenLifetime = TimeSpan.FromDays(10);
                    options.RefreshTokenFormat = format.Object;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.ExtendAsync(token,
                new DateTimeOffset(2017, 01, 15, 00, 00, 00, TimeSpan.Zero),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_DoesNotExtendLifetimeWhenSlidingExpirationIsDisabled()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.DisableSlidingExpiration();

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow ==
                        new DateTimeOffset(2017, 01, 05, 00, 00, 00, TimeSpan.Zero));
                    options.RefreshTokenLifetime = TimeSpan.FromDays(10);
                    options.RefreshTokenFormat = format.Object;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.ExtendAsync(token,
                new DateTimeOffset(2017, 01, 15, 00, 00, 00, TimeSpan.Zero),
                It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSigninResponse_ReturnsErrorResponseWhenExtendingLifetimeOfExistingTokenFailed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId, OpenIdConnectConstants.Scopes.OfflineAccess);

            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            format.Setup(mock => mock.Unprotect("8xLOxBtZp8"))
                .Returns(ticket);

            var token = new OpenIddictToken();

            var manager = CreateTokenManager(instance =>
            {
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                instance.Setup(mock => mock.IsRedeemedAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.ExtendAsync(token, It.IsAny<DateTimeOffset?>(), It.IsAny<CancellationToken>()))
                    .ThrowsAsync(new Exception());
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow ==
                        new DateTimeOffset(2017, 01, 05, 00, 00, 00, TimeSpan.Zero));
                    options.RefreshTokenLifetime = TimeSpan.FromDays(10);
                    options.RefreshTokenFormat = format.Object;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.ExtendAsync(token,
                new DateTimeOffset(2017, 01, 15, 00, 00, 00, TimeSpan.Zero),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_AdHocAuthorizationIsAutomaticallyCreated()
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
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == OpenIddictConstants.AuthorizationTypes.AdHoc),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_CustomPublicParametersAreAddedToAuthorizationResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    var application = new OpenIddictApplication();

                    instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                ["attach-public-parameters"] = true
            });

            // Assert
            Assert.True((bool) response["custom_boolean_parameter"]);
            Assert.Equal(42, (long) response["custom_integer_parameter"]);
            Assert.False(response.HasParameter("custom_json_array_parameter"));
            Assert.False(response.HasParameter("custom_json_object_parameter"));
            Assert.Equal("value", (string) response["custom_string_parameter"]);
        }

        [Fact]
        public async Task ProcessSigninResponse_CustomPublicParametersAreAddedToTokenResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess,
                ["attach-public-parameters"] = true
            });

            // Assert
            Assert.True((bool) response["custom_boolean_parameter"]);
            Assert.Equal(42, (long) response["custom_integer_parameter"]);
            Assert.Equal(new JArray(1, 2, 3), (JArray) response["custom_json_array_parameter"]);
            Assert.Equal(JObject.FromObject(new { Property = "value" }), (JObject) response["custom_json_object_parameter"]);
            Assert.Equal("value", (string) response["custom_string_parameter"]);
        }

        [Fact]
        public async Task ProcessSigninResponse_CustomPublicParametersAreRemovedFromTicket()
        {
            // Arrange
            var format = new Mock<ISecureDataFormat<AuthenticationTicket>>();

            format.Setup(mock => mock.Protect(It.IsAny<AuthenticationTicket>()))
                .Returns("8xLOxBtZp8");

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.AccessTokenFormat = format.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIdConnectConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess,
                ["attach-public-parameters"] = true
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            format.Verify(mock => mock.Protect(
                It.Is<AuthenticationTicket>(ticket =>
                    !ticket.Properties.Items.Any(property => property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Boolean)) &&
                    !ticket.Properties.Items.Any(property => property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Integer)) &&
                    !ticket.Properties.Items.Any(property => property.Key.EndsWith(OpenIddictConstants.PropertyTypes.Json)) &&
                    !ticket.Properties.Items.Any(property => property.Key.EndsWith(OpenIddictConstants.PropertyTypes.String)))));
        }

        [Fact]
        public async Task ProcessSignoutResponse_CustomPublicParametersAreAddedToLogoutResponse()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateApplicationManager(instance =>
                {
                    instance.Setup(mock => mock.ValidatePostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(LogoutEndpoint, new OpenIdConnectRequest
            {
                PostLogoutRedirectUri = "http://www.fabrikam.com/path",
                State = "af0ifjsldkj",
                ["attach-public-parameters"] = true
            });

            // Assert
            Assert.True((bool) response["custom_boolean_parameter"]);
            Assert.Equal(42, (long) response["custom_integer_parameter"]);
            Assert.False(response.HasParameter("custom_json_array_parameter"));
            Assert.False(response.HasParameter("custom_json_object_parameter"));
            Assert.Equal("value", (string) response["custom_string_parameter"]);
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIddictBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddOptions();
                services.AddDistributedMemoryCache();

                // Note: the following client_id/client_secret are fake and are only
                // used to test the metadata returned by the discovery endpoint.
                services.AddAuthentication()
                    .AddFacebook(options =>
                    {
                        options.ClientId = "16018790-E88E-4553-8036-BB342579FF19";
                        options.ClientSecret = "3D6499AF-5607-489B-815A-F3ACF1617296";
                        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    })

                    .AddGoogle(options =>
                    {
                        options.ClientId = "BAF437A5-87FA-4D06-8EFD-F9BA96CCEDC4";
                        options.ClientSecret = "27DF07D3-6B03-4EE0-95CD-3AC16782216B";
                        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    });

                // Replace the default OpenIddict managers.
                services.AddSingleton(CreateApplicationManager());
                services.AddSingleton(CreateAuthorizationManager());
                services.AddSingleton(CreateScopeManager());
                services.AddSingleton(CreateTokenManager());

                services.AddOpenIddict(options =>
                {
                    // Disable the transport security requirement during testing.
                    options.DisableHttpsRequirement();

                    // Enable the tested endpoints.
                    options.EnableAuthorizationEndpoint(AuthorizationEndpoint)
                           .EnableIntrospectionEndpoint(IntrospectionEndpoint)
                           .EnableLogoutEndpoint(LogoutEndpoint)
                           .EnableRevocationEndpoint(RevocationEndpoint)
                           .EnableTokenEndpoint(TokenEndpoint)
                           .EnableUserinfoEndpoint(UserinfoEndpoint);

                    // Enable the tested flows.
                    options.AllowAuthorizationCodeFlow()
                           .AllowClientCredentialsFlow()
                           .AllowImplicitFlow()
                           .AllowPasswordFlow()
                           .AllowRefreshTokenFlow();

                    // Register the X.509 certificate used to sign the identity tokens.
                    options.AddSigningCertificate(
                        assembly: typeof(OpenIddictProviderTests).GetTypeInfo().Assembly,
                        resource: "OpenIddict.Tests.Certificate.pfx",
                        password: "OpenIddict");

                    // Note: overriding the default data protection provider is not necessary for the tests to pass,
                    // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                    // helps make the unit tests run faster, as no registry or disk access is required in this case.
                    options.UseDataProtectionProvider(new EphemeralDataProtectionProvider(new LoggerFactory()));

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });
            });

            builder.Configure(app =>
            {
                app.UseStatusCodePages(context =>
                {
                    context.HttpContext.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.HttpContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        error_custom = OpenIdConnectConstants.Errors.InvalidRequest
                    }));
                });

                app.Use(next => context =>
                {
                    if (context.Request.Path != "/authorize-status-code-middleware" &&
                        context.Request.Path != "/logout-status-code-middleware")
                    {
                        var feature = context.Features.Get<IStatusCodePagesFeature>();
                        feature.Enabled = false;
                    }

                    return next(context);
                });

                app.UseAuthentication();

                app.Run(context =>
                {
                    var request = context.GetOpenIdConnectRequest();
                    if (request == null)
                    {
                        return Task.CompletedTask;
                    }

                    var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                    identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIdConnectServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(request.GetScopes());

                    if (request.HasParameter("attach-authorization"))
                    {
                        ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId, "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70");
                    }

                    if (request.HasParameter("attach-public-parameters"))
                    {
                        ticket.SetProperty("custom_boolean_parameter" + OpenIddictConstants.PropertyTypes.Boolean, "true");
                        ticket.SetProperty("custom_integer_parameter" + OpenIddictConstants.PropertyTypes.Integer, "42");

                        ticket.SetProperty("custom_json_array_parameter" + OpenIddictConstants.PropertyTypes.Json,
                            new JArray(1, 2, 3).ToString());
                        ticket.SetProperty("custom_json_object_parameter" + OpenIddictConstants.PropertyTypes.Json,
                            JObject.FromObject(new { Property = "value" }).ToString());

                        ticket.SetProperty("custom_string_parameter" + OpenIddictConstants.PropertyTypes.String, "value");
                    }

                    if (request.IsAuthorizationRequest() || request.IsTokenRequest())
                    {
                        if (request.HasParameter("deny-authorization"))
                        {
                            return context.ForbidAsync(OpenIdConnectServerDefaults.AuthenticationScheme, ticket.Properties);
                        }

                        if (request.HasParameter("do-not-flow-original-properties"))
                        {
                            var properties = new AuthenticationProperties();
                            properties.SetProperty("custom_property_in_new_ticket", "new_value");

                            return context.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, properties);
                        }

                        return context.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);
                    }

                    else if (request.IsLogoutRequest())
                    {
                        return context.SignOutAsync(OpenIdConnectServerDefaults.AuthenticationScheme, ticket.Properties);
                    }

                    else if (request.IsUserinfoRequest())
                    {
                        context.Response.Headers[HeaderNames.ContentType] = "application/json";

                        return context.Response.WriteAsync(JsonConvert.SerializeObject(new
                        {
                            access_token = request.AccessToken,
                            sub = "Bob le Bricoleur"
                        }));
                    }

                    return Task.FromResult(0);
                });
            });

            return new TestServer(builder);
        }

        private static OpenIddictApplicationManager<OpenIddictApplication> CreateApplicationManager(
            Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>> configuration = null)
        {
            var manager = new Mock<OpenIddictApplicationManager<OpenIddictApplication>>(
                Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>(),
                Mock.Of<ILogger<OpenIddictApplicationManager<OpenIddictApplication>>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(
            Action<Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>> configuration = null)
        {
            var manager = new Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(
                Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>(),
                Mock.Of<ILogger<OpenIddictAuthorizationManager<OpenIddictAuthorization>>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictScopeManager<OpenIddictScope> CreateScopeManager(
            Action<Mock<OpenIddictScopeManager<OpenIddictScope>>> configuration = null)
        {
            var manager = new Mock<OpenIddictScopeManager<OpenIddictScope>>(
                Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>(),
                Mock.Of<ILogger<OpenIddictScopeManager<OpenIddictScope>>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(
            Action<Mock<OpenIddictTokenManager<OpenIddictToken>>> configuration = null)
        {
            var manager = new Mock<OpenIddictTokenManager<OpenIddictToken>>(
                Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>(),
                Mock.Of<ILogger<OpenIddictTokenManager<OpenIddictToken>>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }
    }
}
