/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public partial class OpenIddictServerProviderTests
    {
        [Fact]
        public async Task ExtractAuthorizationRequest_UnsupportedRequestParameterIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                Request = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vd3d3LmZhYnJpa2FtLmNvbSIsImF1ZCI6Imh0" +
                          "dHA6Ly93d3cuY29udG9zby5jb20iLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6" +
                          "IkZhYnJpa2FtIiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL3d3dy5mYWJyaWthbS5jb20vcGF0aCJ9.",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
                Scope = OpenIddictConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.RequestNotSupported, response.Error);
            Assert.Equal("The 'request' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_UnsupportedRequestUriParameterIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                RequestUri = "http://www.fabrikam.com/request/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
                Scope = OpenIddictConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.RequestUriNotSupported, response.Error);
            Assert.Equal("The 'request_uri' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_RequestIdParameterIsRejectedWhenRequestCachingIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'request_id' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_InvalidRequestIdParameterIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddDistributedMemoryCache();

                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                RequestId = "EFAF3596-F868-497F-96BB-AA2AD1F8B7E7"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'request_id' parameter is invalid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_NoneFlowIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.None
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_UnknownResponseTypeParameterIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = "unknown_response_type"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not supported.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode, "code")]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode, "code id_token")]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode, "code id_token token")]
        [InlineData(OpenIddictConstants.GrantTypes.AuthorizationCode, "code token")]
        [InlineData(OpenIddictConstants.GrantTypes.Implicit, "code id_token")]
        [InlineData(OpenIddictConstants.GrantTypes.Implicit, "code id_token token")]
        [InlineData(OpenIddictConstants.GrantTypes.Implicit, "code token")]
        [InlineData(OpenIddictConstants.GrantTypes.Implicit, "id_token")]
        [InlineData(OpenIddictConstants.GrantTypes.Implicit, "id_token token")]
        [InlineData(OpenIddictConstants.GrantTypes.Implicit, "token")]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCorrespondingFlowIsDisabled(string flow, string type)
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.GrantTypes.Remove(flow));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIddictConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenUnregisteredScopeIsSpecified()
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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
                Scope = "unregistered_scope"
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidScope, response.Error);
            Assert.Equal("The specified 'scope' parameter is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenScopeRegisteredInOptionsIsSpecified()
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

                builder.RegisterScopes("registered_scope");
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Token,
                Scope = "registered_scope"
            });

            // Assert
            Assert.Null(response.Error);
            Assert.Null(response.ErrorDescription);
            Assert.Null(response.ErrorUri);
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenRegisteredScopeIsSpecified()
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

                builder.RegisterScopes("scope_registered_in_options");

                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Token,
                Scope = "scope_registered_in_database scope_registered_in_options"
            });

            // Assert
            Assert.Null(response.Error);
            Assert.Null(response.ErrorDescription);
            Assert.Null(response.ErrorUri);
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.GrantTypes.Remove(OpenIddictConstants.GrantTypes.RefreshToken));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
                Scope = OpenIddictConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'offline_access' scope is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_UnknownResponseModeParameterIsRejected()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseMode = "unknown_response_mode",
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'response_mode' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = null,
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'redirect_uri' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenPkceIsRequiredAndCodeChallengeIsMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder => builder.RequireProofKeyForCodeExchange());

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = null,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'code_challenge' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsMissing()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = null,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'code_challenge_method' parameter must be specified.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsPlain()
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = OpenIdConnectConstants.CodeChallengeMethods.Plain,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'code_challenge_method' parameter is not allowed.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        public async Task ValidateAuthorizationRequest_CodeChallengeRequestWithForbiddenResponseTypeIsRejected(string type)
        {
            // Arrange
            var server = CreateAuthorizationServer();

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = OpenIdConnectConstants.CodeChallengeMethods.Sha256,
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIddictConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not allowed when using PKCE.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenClientCannotBeFound()
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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'client_id' parameter is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task ValidateAuthorizationRequest_AnAccessTokenCannotBeReturnedWhenClientIsConfidential(string type)
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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIddictConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreEndpointPermissions = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the authorization endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData(
            "code",
            new[] { OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode },
            "The client application is not allowed to use the authorization code flow.")]
        [InlineData(
            "code id_token",
            new[] { OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddictConstants.Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the hybrid flow.")]
        [InlineData(
            "code id_token token",
            new[] { OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddictConstants.Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the hybrid flow.")]
        [InlineData(
            "code token",
            new[] { OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, OpenIddictConstants.Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the hybrid flow.")]
        [InlineData(
            "id_token",
            new[] { OpenIddictConstants.Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the implicit flow.")]
        [InlineData(
            "id_token token",
            new[] { OpenIddictConstants.Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the implicit flow.")]
        [InlineData(
            "token",
            new[] { OpenIddictConstants.Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the implicit flow.")]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenGrantTypePermissionIsNotGranted(
            string type, string[] permissions, string description)
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                foreach (var permission in permissions)
                {
                    instance.Setup(mock => mock.HasPermissionAsync(application, permission, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);
                }
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);

                builder.Configure(options => options.IgnoreGrantTypePermissions = false);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIddictConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.UnauthorizedClient, response.Error);
            Assert.Equal(description, response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application, permissions[0], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.HasPermissionAsync(application,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, It.IsAny<CancellationToken>()))
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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
                Scope = OpenIddictConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The client application is not allowed to use the 'offline_access' scope.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsInvalid()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var server = CreateAuthorizationServer(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'redirect_uri' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenScopePermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

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
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Code,
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
        public async Task HandleAuthorizationRequest_RequestIsPersistedInDistributedCache()
        {
            // Arrange
            var cache = new Mock<IDistributedCache>();
            var generator = new Mock<RandomNumberGenerator>();

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

                builder.Services.AddSingleton(cache.Object);

                builder.EnableRequestCaching();

                builder.SetRequestCachingPolicy(new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(42),
                    SlidingExpiration = TimeSpan.FromSeconds(42)
                });

                builder.Configure(options => options.RandomNumberGenerator = generator.Object);
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Token
            });

            var identifier = (string) response[OpenIddictConstants.Parameters.RequestId];

            // Assert
            Assert.Single(response.GetParameters());
            Assert.NotNull(identifier);

            cache.Verify(mock => mock.SetAsync(
                OpenIddictConstants.Environment.AuthorizationRequest + identifier,
                It.IsAny<byte[]>(),
                It.Is<DistributedCacheEntryOptions>(options =>
                    options.AbsoluteExpirationRelativeToNow == TimeSpan.FromDays(42) &&
                    options.SlidingExpiration == TimeSpan.FromSeconds(42)),
                It.IsAny<CancellationToken>()), Times.Once());

            generator.Verify(mock => mock.GetBytes(It.Is<byte[]>(bytes => bytes.Length == 256 / 8)), Times.Once());
        }

        [Theory]
        [InlineData("code")]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task HandleAuthorizationRequest_RequestsAreNotHandledLocally(string type)
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

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("3E228451-1555-46F7-A471-951EFBA23A56"));
                }));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = OpenIddictConstants.Scopes.OpenId
            });

            // Assert
            Assert.True(!string.IsNullOrEmpty(response.AccessToken) ||
                        !string.IsNullOrEmpty(response.Code) ||
                        !string.IsNullOrEmpty(response.IdToken));
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_RequestIsRemovedFromDistributedCache()
        {
            // Arrange
            var request = new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIddictConstants.ResponseTypes.Token
            };

            var stream = new MemoryStream();
            using (var writer = new BsonDataWriter(stream))
            {
                writer.CloseOutput = false;

                var serializer = JsonSerializer.CreateDefault();
                serializer.Serialize(writer, request);
            }

            var cache = new Mock<IDistributedCache>();

            cache.Setup(mock => mock.GetAsync(
                OpenIddictConstants.Environment.AuthorizationRequest + "b2ee7815-5579-4ff7-86b0-ba671b939d96",
                It.IsAny<CancellationToken>()))
                .ReturnsAsync(stream.ToArray());

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

                builder.Services.AddSingleton(cache.Object);

                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                RequestId = "b2ee7815-5579-4ff7-86b0-ba671b939d96"
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            cache.Verify(mock => mock.RemoveAsync(
                OpenIddictConstants.Environment.AuthorizationRequest + "b2ee7815-5579-4ff7-86b0-ba671b939d96",
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_SupportsNullRequests()
        {
            // Note: when an invalid HTTP verb is used, the OpenID Connect server handler refuses to extract the request
            // and immediately returns an error. In this specific case, ApplyAuthorizationResponseContext.Request is null
            // and this test ensures ApplyAuthorizationResponse can safely handle cases where the request is unavailable.

            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.SendAsync(HttpMethods.Put, AuthorizationEndpoint, new OpenIdConnectRequest());

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified HTTP method is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_ErroredRequestIsNotHandledLocallyWhenStatusCodeMiddlewareIsEnabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.EnableAuthorizationEndpoint("/authorize-status-code-middleware");
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync("/authorize-status-code-middleware", new OpenIdConnectRequest
            {
                ClientId = null,
                RedirectUri = null,
                ResponseType = null
            });

            // Assert
            Assert.Equal(OpenIddictConstants.Errors.InvalidRequest, (string) response["error_custom"]);
        }
    }
}
