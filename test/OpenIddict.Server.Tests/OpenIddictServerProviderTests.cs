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
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public partial class OpenIddictServerProviderTests
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
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
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIddictConstants.Scopes.OfflineAccess,
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
        public async Task ProcessSigninResponse_ThrowsAnExceptionForInvalidIdentity()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
                {
                    GrantType = OpenIddictConstants.GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w",
                    ["use-null-authentication-type"] = true
                });
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified principal doesn't contain a valid or authenticated identity.")
                .Append("Make sure that both 'ClaimsPrincipal.Identity' and 'ClaimsPrincipal.Identity.AuthenticationType' ")
                .Append("are not null and that 'ClaimsPrincipal.Identity.IsAuthenticated' returns 'true'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessSigninResponse_AuthenticationPropertiesAreAutomaticallyRestored()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);
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
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
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
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetPresenters("Fabrikam");
            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.AuthorizationCode);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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

                builder.UseRollingTokens();

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
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsAlwaysIssuedWhenRollingTokensAreEnabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsNotIssuedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSigninResponse_AuthorizationCodeIsAutomaticallyRedeemed()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
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
            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_ReturnsErrorResponseWhenRedeemingAuthorizationCodeFails()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
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
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsAutomaticallyRedeemedWhenRollingTokensAreEnabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
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
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_RefreshTokenIsNotRedeemedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
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
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

                instance.Setup(mock => mock.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("481FCAC6-06BC-43EE-92DB-37A78AA09B595073CC313103"));

                instance.Setup(mock => mock.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8"));

                instance.Setup(mock => mock.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0"));

                instance.Setup(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    var authorization = new OpenIddictAuthorization();

                    instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(authorization);

                    instance.Setup(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                builder.Services.AddSingleton(manager);

                builder.UseRollingTokens();

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
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_PreviousTokensAreNotRevokedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var identity = new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme);
            identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Bricoleur");

            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);
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
                instance.Setup(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                instance.Setup(mock => mock.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

                instance.Setup(mock => mock.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("481FCAC6-06BC-43EE-92DB-37A78AA09B595073CC313103"));

                instance.Setup(mock => mock.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8"));

                instance.Setup(mock => mock.IsRedeemedAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                instance.Setup(mock => mock.IsValidAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(CreateAuthorizationManager(instance =>
                {
                    var authorization = new OpenIddictAuthorization();

                    instance.Setup(mock => mock.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(authorization);

                    instance.Setup(mock => mock.IsValidAsync(authorization, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
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
            Assert.NotNull(response.AccessToken);
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(mock => mock.RevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Never());
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
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
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
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.ExtendAsync(token,
                new DateTimeOffset(2017, 01, 15, 00, 00, 00, TimeSpan.Zero),
                It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSigninResponse_DoesNotUpdateExpirationDateWhenAlreadyNull()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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

                instance.Setup(mock => mock.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<DateTimeOffset?>(result: null));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow ==
                        new DateTimeOffset(2017, 01, 05, 00, 00, 00, TimeSpan.Zero));
                    options.RefreshTokenLifetime = null;
                    options.RefreshTokenFormat = format.Object;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.ExtendAsync(token, null, It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSigninResponse_SetsExpirationDateToNullWhenLifetimeIsNull()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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

                instance.Setup(mock => mock.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<DateTimeOffset?>(DateTimeOffset.Now + TimeSpan.FromDays(1)));
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options =>
                {
                    options.SystemClock = Mock.Of<ISystemClock>(mock => mock.UtcNow ==
                        new DateTimeOffset(2017, 01, 05, 00, 00, 00, TimeSpan.Zero));
                    options.RefreshTokenLifetime = null;
                    options.RefreshTokenFormat = format.Object;
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(TokenEndpoint, new OpenIdConnectRequest
            {
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(mock => mock.ExtendAsync(token, null, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSigninResponse_IgnoresErrorWhenExtendingLifetimeOfExistingTokenFailed()
        {
            // Arrange
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(),
                new AuthenticationProperties(),
                OpenIddictServerDefaults.AuthenticationScheme);

            ticket.SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");
            ticket.SetTokenUsage(OpenIdConnectConstants.TokenUsages.RefreshToken);
            ticket.SetScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess);

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
                    .Returns(new ValueTask<string>("60FFF7EA-F98E-437B-937E-5073CC313103"));

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
                GrantType = OpenIddictConstants.GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.AccessToken);

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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));
                }));

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
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
        public async Task ProcessSigninResponse_AdHocAuthorizationIsNotCreatedWhenAuthorizationStorageIsDisabled()
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));
                }));

                builder.Services.AddSingleton(manager);

                builder.DisableAuthorizationStorage();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(mock => mock.CreateAsync(It.IsAny<OpenIddictAuthorizationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
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
                        .Returns(new ValueTask<string>(OpenIddictConstants.ClientTypes.Public));
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
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
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIddictConstants.Scopes.OfflineAccess,
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
                GrantType = OpenIddictConstants.GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = OpenIddictConstants.Scopes.OfflineAccess,
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
                    instance.Setup(mock => mock.FindByPostLogoutRedirectUriAsync("http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ImmutableArray.Create(new OpenIddictApplication()));
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

        private static TestServer CreateAuthorizationServer(Action<OpenIddictServerBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddOptions();
                services.AddDistributedMemoryCache();

                services.AddOpenIddict()
                    .AddCore(options =>
                    {
                        options.SetDefaultApplicationEntity<OpenIddictApplication>()
                               .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                               .SetDefaultScopeEntity<OpenIddictScope>()
                               .SetDefaultTokenEntity<OpenIddictToken>();

                        options.Services.AddSingleton(CreateApplicationManager())
                                        .AddSingleton(CreateAuthorizationManager())
                                        .AddSingleton(CreateScopeManager())
                                        .AddSingleton(CreateTokenManager());
                    })

                    .AddServer(options =>
                    {
                        // Accept anonymous clients by default.
                        options.AcceptAnonymousClients();

                        // Disable permission enforcement by default.
                        options.IgnoreEndpointPermissions()
                               .IgnoreGrantTypePermissions()
                               .IgnoreScopePermissions();

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
                            assembly: typeof(OpenIddictServerProviderTests).GetTypeInfo().Assembly,
                            resource: "OpenIddict.Server.Tests.Certificate.pfx",
                            password: "OpenIddict");

                        // Note: overriding the default data protection provider is not necessary for the tests to pass,
                        // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                        // helps make the unit tests run faster, as no registry or disk access is required in this case.
                        options.UseDataProtectionProvider(new EphemeralDataProtectionProvider());

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
                        error_custom = OpenIddictConstants.Errors.InvalidRequest
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

                    var identity = !request.HasParameter("use-null-authentication-type") ?
                        new ClaimsIdentity(OpenIddictServerDefaults.AuthenticationScheme) :
                        new ClaimsIdentity();

                    identity.AddClaim(OpenIddictConstants.Claims.Subject, "Bob le Magnifique");

                    var ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        OpenIddictServerDefaults.AuthenticationScheme);

                    ticket.SetScopes(request.GetScopes());

                    if (request.HasParameter("attach-authorization"))
                    {
                        ticket.SetInternalAuthorizationId("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70");
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
                            return context.ForbidAsync(OpenIddictServerDefaults.AuthenticationScheme, ticket.Properties);
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
                        return context.SignOutAsync(OpenIddictServerDefaults.AuthenticationScheme, ticket.Properties);
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

                    return Task.CompletedTask;
                });
            });

            return new TestServer(builder);
        }

        private static OpenIddictApplicationManager<OpenIddictApplication> CreateApplicationManager(
            Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>> configuration = null)
        {
            var manager = new Mock<OpenIddictApplicationManager<OpenIddictApplication>>(
                Mock.Of<IOpenIddictApplicationCache<OpenIddictApplication>>(),
                Mock.Of<IOpenIddictApplicationStoreResolver>(),
                Mock.Of<ILogger<OpenIddictApplicationManager<OpenIddictApplication>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(
            Action<Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>> configuration = null)
        {
            var manager = new Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(
                Mock.Of<IOpenIddictAuthorizationCache<OpenIddictAuthorization>>(),
                Mock.Of<IOpenIddictAuthorizationStoreResolver>(),
                Mock.Of<ILogger<OpenIddictAuthorizationManager<OpenIddictAuthorization>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictScopeManager<OpenIddictScope> CreateScopeManager(
            Action<Mock<OpenIddictScopeManager<OpenIddictScope>>> configuration = null)
        {
            var manager = new Mock<OpenIddictScopeManager<OpenIddictScope>>(
                Mock.Of<IOpenIddictScopeCache<OpenIddictScope>>(),
                Mock.Of<IOpenIddictScopeStoreResolver>(),
                Mock.Of<ILogger<OpenIddictScopeManager<OpenIddictScope>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(
            Action<Mock<OpenIddictTokenManager<OpenIddictToken>>> configuration = null)
        {
            var manager = new Mock<OpenIddictTokenManager<OpenIddictToken>>(
                Mock.Of<IOpenIddictTokenCache<OpenIddictToken>>(),
                Mock.Of<IOpenIddictTokenStoreResolver>(),
                Mock.Of<ILogger<OpenIddictTokenManager<OpenIddictToken>>>(),
                Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>());

            configuration?.Invoke(manager);

            return manager.Object;
        }

        public class OpenIddictApplication { }
        public class OpenIddictAuthorization { }
        public class OpenIddictScope { }
        public class OpenIddictToken { }
    }
}
