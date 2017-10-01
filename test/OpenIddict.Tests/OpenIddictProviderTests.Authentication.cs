/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.IO;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Client;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests
{
    public partial class OpenIddictProviderTests
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.RequestNotSupported, response.Error);
            Assert.Equal("The request parameter is not supported.", response.ErrorDescription);
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.RequestUriNotSupported, response.Error);
            Assert.Equal("The request_uri parameter is not supported.", response.ErrorDescription);
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
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The request_id parameter is not supported.", response.ErrorDescription);
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
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Invalid request: timeout expired.", response.ErrorDescription);
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
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified response_type parameter is not supported.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode, "code")]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode, "code id_token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode, "code id_token token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.AuthorizationCode, "code token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit, "code id_token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit, "code id_token token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit, "code token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit, "id_token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit, "id_token token")]
        [InlineData(OpenIdConnectConstants.GrantTypes.Implicit, "token")]
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
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified response_type parameter is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.GrantTypes.Remove(OpenIdConnectConstants.GrantTypes.RefreshToken));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code,
                Scope = OpenIdConnectConstants.Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified response_mode parameter is not supported.", response.ErrorDescription);
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The required redirect_uri parameter was missing.", response.ErrorDescription);
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified code_challenge_method parameter is not allowed.", response.ErrorDescription);
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
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified response_type parameter is not allowed when using PKCE.", response.ErrorDescription);
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Application not found in the database: ensure that your client_id is correct.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Code
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Invalid redirect_uri.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task ValidateAuthorizationRequest_ImplicitOrHybridRequestIsRejectedWhenClientIsConfidential(string type)
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(instance =>
            {
                instance.Setup(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                instance.Setup(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                instance.Setup(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(OpenIddictConstants.ClientTypes.Confidential);
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
                Scope = OpenIdConnectConstants.Scopes.OpenId
            });

            // Assert
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, response.Error);
            Assert.Equal("Confidential clients are not allowed to retrieve a token from the authorization endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(mock => mock.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(mock => mock.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleAuthorizationRequest_RequestIsPersistedInDistributedCache()
        {
            // Arrange
            var cache = new Mock<IDistributedCache>();

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

                builder.Services.AddSingleton(cache.Object);

                builder.EnableRequestCaching();
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act
            var response = await client.PostAsync(AuthorizationEndpoint, new OpenIdConnectRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = OpenIdConnectConstants.ResponseTypes.Token
            });

            var identifier = (string) response[OpenIdConnectConstants.Parameters.RequestId];

            // Assert
            Assert.Single(response.GetParameters());
            Assert.NotNull(identifier);

            cache.Verify(mock => mock.SetAsync(
                OpenIddictConstants.Environment.AuthorizationRequest + identifier,
                It.IsAny<byte[]>(),
                It.IsAny<DistributedCacheEntryOptions>(),
                It.IsAny<CancellationToken>()), Times.Once());
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
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);

                    instance.Setup(mock => mock.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                builder.Services.AddSingleton(CreateTokenManager(instance =>
                {
                    var token = new OpenIddictToken();

                    instance.Setup(mock => mock.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    instance.Setup(mock => mock.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
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
                Scope = OpenIdConnectConstants.Scopes.OpenId
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
                ResponseType = OpenIdConnectConstants.ResponseTypes.Token
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
                        .ReturnsAsync(OpenIddictConstants.ClientTypes.Public);
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
        public async Task ApplyAuthorizationResponse_ErroredRequestIsNotHandledLocallyWhenStatusCodeMiddlewareIsEnabled()
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
            Assert.Equal(OpenIdConnectConstants.Errors.InvalidRequest, (string) response["error_custom"]);
        }
    }
}
