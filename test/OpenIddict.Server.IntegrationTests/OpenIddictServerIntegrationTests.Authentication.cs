/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.FunctionalTests
{
    public abstract partial class OpenIddictServerIntegrationTests
    {
        [Theory]
        [InlineData(nameof(HttpMethod.Delete))]
        [InlineData(nameof(HttpMethod.Head))]
        [InlineData(nameof(HttpMethod.Options))]
        [InlineData(nameof(HttpMethod.Put))]
        [InlineData(nameof(HttpMethod.Trace))]
        public async Task ExtractAuthorizationRequest_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.SendAsync(method, "/connect/authorize", new OpenIddictRequest());

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified HTTP method is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_UnsupportedRequestParameterIsRejected()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                Request = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vd3d3LmZhYnJpa2FtLmNvbSIsImF1ZCI6Imh0" +
                          "dHA6Ly93d3cuY29udG9zby5jb20iLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6" +
                          "IkZhYnJpa2FtIiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL3d3dy5mYWJyaWthbS5jb20vcGF0aCJ9.",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.RequestNotSupported, response.Error);
            Assert.Equal("The 'request' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_UnsupportedRequestUriParameterIsRejected()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                RequestUri = "http://www.fabrikam.com/request/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.RequestUriNotSupported, response.Error);
            Assert.Equal("The 'request_uri' parameter is not supported.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ExtractAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/connect/authorize");

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Magnifique"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/connect/authorize");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ExtractAuthorizationRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/connect/authorize");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_MissingClientIdCausesAnError()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = null
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_MissingRedirectUriCausesAnErrorForOpenIdRequests()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = null,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'redirect_uri' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("/path", "The 'redirect_uri' parameter must be a valid absolute URL.")]
        [InlineData("/tmp/file.xml", "The 'redirect_uri' parameter must be a valid absolute URL.")]
        [InlineData("C:\\tmp\\file.xml", "The 'redirect_uri' parameter must be a valid absolute URL.")]
        [InlineData("http://www.fabrikam.com/path#param=value", "The 'redirect_uri' parameter must not include a fragment.")]
        public async Task ValidateAuthorizationRequest_InvalidRedirectUriCausesAnError(string address, string message)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = address,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(message, response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_MissingResponseTypeCausesAnError()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = null,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'response_type' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token", ResponseModes.Query)]
        [InlineData("code id_token token", ResponseModes.Query)]
        [InlineData("code token", ResponseModes.Query)]
        [InlineData("id_token", ResponseModes.Query)]
        [InlineData("id_token token", ResponseModes.Query)]
        [InlineData("token", ResponseModes.Query)]
        public async Task ValidateAuthorizationRequest_UnsafeResponseModeCausesAnError(string type, string mode)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseMode = mode,
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'response_type'/'response_mode' combination is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task ValidateAuthorizationRequest_MissingNonceCausesAnErrorForOpenIdRequests(string type)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'nonce' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        public async Task ValidateAuthorizationRequest_MissingOpenIdScopeCausesAnErrorForOpenIdRequests(string type)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'openid' scope is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("none consent")]
        [InlineData("none login")]
        [InlineData("none select_account")]
        public async Task ValidateAuthorizationRequest_InvalidPromptCausesAnError(string prompt)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                Prompt = prompt,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = "code id_token token",
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'prompt' parameter is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("none")]
        [InlineData("consent")]
        [InlineData("login")]
        [InlineData("select_account")]
        [InlineData("consent login")]
        [InlineData("consent select_account")]
        [InlineData("login select_account")]
        [InlineData("consent login select_account")]
        public async Task ValidateAuthorizationRequest_ValidPromptDoesNotCauseAnError(string prompt)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                Prompt = prompt,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = "code id_token token",
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Null(response.Error);
            Assert.Null(response.ErrorDescription);
            Assert.NotNull(response.AccessToken);
            Assert.NotNull(response.Code);
            Assert.NotNull(response.IdToken);
        }

        [Theory]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task ValidateAuthorizationRequest_MissingCodeResponseTypeCausesAnErrorWhenCodeChallengeIsUsed(string type)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = CodeChallengeMethods.Sha256,
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'code_challenge' and 'code_challenge_method' parameters " +
                         "can only be used with a response type containing 'code'.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_MissingCodeChallengeCausesAnErrorWhenCodeChallengeMethodIsSpecified()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                CodeChallengeMethod = CodeChallengeMethods.Sha256,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'code_challenge_method' parameter " +
                         "cannot be used without 'code_challenge'.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_InvalidCodeChallengeMethodCausesAnError()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = "invalid_code_challenge_method",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified code_challenge_method is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_NoneFlowIsRejected()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.None
            });

            // Assert
            Assert.Equal(Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_UnknownResponseTypeParameterIsRejected()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = "unknown_response_type"
            });

            // Assert
            Assert.Equal(Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not allowed.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(GrantTypes.AuthorizationCode, "code")]
        [InlineData(GrantTypes.AuthorizationCode, "code id_token")]
        [InlineData(GrantTypes.AuthorizationCode, "code id_token token")]
        [InlineData(GrantTypes.AuthorizationCode, "code token")]
        [InlineData(GrantTypes.Implicit, "code id_token")]
        [InlineData(GrantTypes.Implicit, "code id_token token")]
        [InlineData(GrantTypes.Implicit, "code token")]
        [InlineData(GrantTypes.Implicit, "id_token")]
        [InlineData(GrantTypes.Implicit, "id_token token")]
        [InlineData(GrantTypes.Implicit, "token")]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCorrespondingFlowIsDisabled(string flow, string type)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Configure(options => options.GrantTypes.Remove(flow));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.UnsupportedResponseType, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenUnregisteredScopeIsSpecified()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<OpenIddictApplication>(application));

                    mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<bool>(true));

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(ClientTypes.Public));
                }));

                options.Services.AddSingleton(CreateScopeManager(mock =>
                {
                    mock.Setup(manager => manager.FindByNamesAsync(
                        It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "unregistered_scope"),
                        It.IsAny<CancellationToken>()))
                        .Returns(AsyncEnumerable.Empty<OpenIddictScope>());
                }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = "unregistered_scope"
            });

            // Assert
            Assert.Equal(Errors.InvalidScope, response.Error);
            Assert.Equal("The specified 'scope' parameter is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenScopeRegisteredInOptionsIsSpecified()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<OpenIddictApplication>(application));

                    mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<bool>(true));

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(ClientTypes.Public));
                }));

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<OpenIddictApplication>(application));

                    mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<bool>(true));

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(ClientTypes.Public));
                }));

                options.RegisterScopes("registered_scope");
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Token,
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
            var client = CreateClient(options =>
            {
                var scope = new OpenIddictScope();

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<OpenIddictApplication>(application));

                    mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<bool>(true));

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>(ClientTypes.Public));
                }));

                options.Services.AddSingleton(CreateScopeManager(mock =>
                {
                    mock.Setup(manager => manager.FindByNamesAsync(
                        It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "scope_registered_in_database"),
                        It.IsAny<CancellationToken>()))
                        .Returns(new[] { scope }.ToAsyncEnumerable());

                    mock.Setup(manager => manager.GetNameAsync(scope, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<string>("scope_registered_in_database"));
                }));

                options.RegisterScopes("scope_registered_in_options");
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Token,
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
            var client = CreateClient(options =>
            {
                options.Configure(options => options.GrantTypes.Remove(GrantTypes.RefreshToken));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'offline_access' scope is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_UnknownResponseModeParameterIsRejected()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseMode = "unknown_response_mode",
                ResponseType = ResponseTypes.Code
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'response_mode' parameter is not supported.", response.ErrorDescription);
        }

        [Fact(Skip = "The handler responsible of rejecting such requests has not been ported.")]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsMissing()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = null,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'code_challenge_method' parameter must be specified.", response.ErrorDescription);
        }

        [Fact(Skip = "The handler responsible of rejecting such requests has not been ported.")]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsPlain()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = CodeChallengeMethods.Plain,
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'code_challenge_method' parameter is not allowed.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        public async Task ValidateAuthorizationRequest_CodeChallengeRequestWithForbiddenResponseTypeIsRejected(string type)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                CodeChallengeMethod = CodeChallengeMethods.Sha256,
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not allowed when using PKCE.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsMissing()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = null,
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'redirect_uri' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ValidateAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Magnifique"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_MissingRedirectUriCausesAnException()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/connect/authorize", new OpenIddictRequest
                {
                    ClientId = "Fabrikam",
                    RedirectUri = null,
                    ResponseType = ResponseTypes.Code
                });
            });

            // Assert
            Assert.Equal("The request cannot be validated because no redirect_uri was specified.", exception.Message);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_InvalidRedirectUriCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SetRedirectUri("http://www.contoso.com/path");

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/connect/authorize", new OpenIddictRequest
                {
                    ClientId = "Fabrikam",
                    RedirectUri = "http://www.fabrikam.com/path",
                    ResponseType = ResponseTypes.Code
                });
            });

            // Assert
            Assert.Equal("The authorization request cannot be validated because a different " +
                         "redirect_uri was specified by the client application.", exception.Message);
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenClientCannotBeFound()
        {
            // Arrange
            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<OpenIddictApplication>(result: null));
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'client_id' parameter is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
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

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<OpenIddictApplication>(application));

                mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<string>(ClientTypes.Confidential));
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.UnauthorizedClient, response.Error);
            Assert.Equal("The specified 'response_type' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<OpenIddictApplication>(application));

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(true));

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(false));
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);

                options.Configure(options => options.IgnoreEndpointPermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code
            });

            // Assert
            Assert.Equal(Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the authorization endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Theory]
        [InlineData(
            "code",
            new[] { Permissions.GrantTypes.AuthorizationCode },
            "The client application is not allowed to use the authorization code flow.")]
        [InlineData(
            "code id_token",
            new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the hybrid flow.")]
        [InlineData(
            "code id_token token",
            new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the hybrid flow.")]
        [InlineData(
            "code token",
            new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the hybrid flow.")]
        [InlineData(
            "id_token",
            new[] { Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the implicit flow.")]
        [InlineData(
            "id_token token",
            new[] { Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the implicit flow.")]
        [InlineData(
            "token",
            new[] { Permissions.GrantTypes.Implicit },
            "The client application is not allowed to use the implicit flow.")]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenGrantTypePermissionIsNotGranted(
            string type, string[] permissions, string description)
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<OpenIddictApplication>(application));

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(true));

                foreach (var permission in permissions)
                {
                    mock.Setup(manager => manager.HasPermissionAsync(application, permission, It.IsAny<CancellationToken>()))
                        .Returns(new ValueTask<bool>(false));
                }
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);

                options.Configure(options => options.IgnoreGrantTypePermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.UnauthorizedClient, response.Error);
            Assert.Equal(description, response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application, permissions[0], It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<OpenIddictApplication>(application));

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(true));

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.GrantTypes.AuthorizationCode, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(true));

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(false));
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);

                options.Configure(options => options.IgnoreGrantTypePermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The client application is not allowed to use the 'offline_access' scope.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsInvalid()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<OpenIddictApplication>(application));

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(false));
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'redirect_uri' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenScopePermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<OpenIddictApplication>(application));

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(true));

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.Prefixes.Scope +
                    Scopes.Profile, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(true));

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.Prefixes.Scope +
                    Scopes.Email, It.IsAny<CancellationToken>()))
                    .Returns(new ValueTask<bool>(false));
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
                options.RegisterScopes(Scopes.Email, Scopes.Profile);
                options.Configure(options => options.IgnoreScopePermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = "openid offline_access profile email"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("This client application is not allowed to use the specified scope.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope +
                Scopes.OpenId, It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope +
                Scopes.OfflineAccess, It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope +
                Scopes.Profile, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope +
                Scopes.Email, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task HandleAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task HandleAuthorizationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Magnifique"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleAuthorizationRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData("code", ResponseModes.Query)]
        [InlineData("code id_token", ResponseModes.Fragment)]
        [InlineData("code id_token token", ResponseModes.Fragment)]
        [InlineData("code token", ResponseModes.Fragment)]
        [InlineData("id_token", ResponseModes.Fragment)]
        [InlineData("id_token token", ResponseModes.Fragment)]
        [InlineData("token", ResponseModes.Fragment)]
        public async Task ApplyAuthorizationResponse_ResponseModeIsAutomaticallyInferred(string type, string mode)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Response["inferred_response_mode"] = context.ResponseMode;

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = type,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(mode, (string) response["inferred_response_mode"]);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Magnifique"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Response["custom_parameter"] = "custom_value";
                        context.Response["parameter_with_multiple_values"] = new[]
                        {
                            "custom_value_1",
                            "custom_value_2"
                        };

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_ThrowsAnExceptionWhenRequestIsMissing()
        {
            // Note: an exception is only thrown if the request was not properly extracted
            // AND if the developer decided to override the error to return a custom response.
            // To emulate this behavior, the error property is manually set to null.

            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Response.Error = null;

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.SendAsync(HttpMethod.Put, "/connect/authorize", new OpenIddictRequest());
            });

            Assert.Equal(new StringBuilder()
                .Append("The authorization response was not correctly applied. To apply authorization responses, ")
                .Append("create a class implementing 'IOpenIddictServerHandler<ApplyAuthorizationResponseContext>' ")
                .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_DoesNotSetStateWhenUserIsNotRedirected()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ResponseType = ResponseTypes.Code,
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Null(response.State);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_FlowsStateWhenRedirectUriIsUsed()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("af0ifjsldkj", response.State);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_DoesNotOverrideStateSetByApplicationCode()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Response.State = "custom_state";

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                State = "af0ifjsldkj"
            });

            // Assert
            Assert.Equal("custom_state", response.State);
        }

        [Fact]
        public async Task ApplyAuthorizationResponse_UnsupportedResponseModeCausesAnError()
        {
            // Note: response_mode validation is deliberately delayed until an authorization response
            // is returned to allow implementers to override the ApplyAuthorizationResponse event
            // to support custom response modes. To test this scenario, the request is marked
            // as validated and a signin grant is applied to return an authorization response.

            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseMode = "unsupported_response_mode",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified 'response_mode' parameter is not supported.", response.ErrorDescription);
        }
    }
}
