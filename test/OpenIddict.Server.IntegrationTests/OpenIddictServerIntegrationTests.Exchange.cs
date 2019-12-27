/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace OpenIddict.Server.FunctionalTests
{
    public abstract partial class OpenIddictServerIntegrationTests
    {
        [Theory]
        [InlineData(nameof(HttpMethod.Delete))]
        [InlineData(nameof(HttpMethod.Get))]
        [InlineData(nameof(HttpMethod.Head))]
        [InlineData(nameof(HttpMethod.Options))]
        [InlineData(nameof(HttpMethod.Put))]
        [InlineData(nameof(HttpMethod.Trace))]
        public async Task ExtractTokenRequest_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.SendAsync(method, "/connect/token", new OpenIddictRequest());

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The specified HTTP method is not valid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ExtractTokenRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest());

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ExtractTokenRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Bricoleur"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest());

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ExtractTokenRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest());

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateTokenRequest_MissingGrantTypeCausesAnError()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = null
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'grant_type' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_MissingClientIdCausesAnErrorForCodeFlowRequests()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = null,
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_MissingCodeCausesAnError()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = null,
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'code' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_MissingRefreshTokenCausesAnError()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = null
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'refresh_token' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(null, null)]
        [InlineData("client_id", null)]
        [InlineData(null, "client_secret")]
        public async Task ValidateTokenRequest_MissingClientCredentialsCauseAnError(string identifier, string secret)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = identifier,
                ClientSecret = secret,
                GrantType = GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'client_id' and 'client_secret' parameters are " +
                         "required when using the client credentials grant.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(null, null)]
        [InlineData("username", null)]
        [InlineData(null, "password")]
        public async Task ValidateTokenRequest_MissingUserCredentialsCauseAnError(string username, string password)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = username,
                Password = password
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'username' and/or 'password' parameters are missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ValidateTokenRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ValidateTokenRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Bricoleur"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateTokenRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateTokenRequest_InvalidAuthorizationCodeCausesAnError()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is invalid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_InvalidRefreshTokenCausesAnError()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is invalid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_ExpiredAuthorizationCodeCausesAnError()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetExpirationDate(DateTimeOffset.UtcNow - TimeSpan.FromDays(1));

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is no longer valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_ExpiredRefreshTokenCausesAnError()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetExpirationDate(DateTimeOffset.UtcNow - TimeSpan.FromDays(1));

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is no longer valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenPresentersAreMissing()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters(Enumerable.Empty<string>());

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/connect/token", new OpenIddictRequest
                {
                    ClientId = "Fabrikam",
                    Code = "SplxlOBeZQQYbYS6WxSbIA",
                    GrantType = GrantTypes.AuthorizationCode
                });
            });

            Assert.Equal("The presenters list cannot be extracted from the authorization code.", exception.Message);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenCallerIsNotAPresenter()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Contoso");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code cannot be used by this client application.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RefreshTokenCausesAnErrorWhenCallerIsNotAPresenter()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Contoso");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token cannot be used by this client application.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenRedirectUriIsMissing()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Private.RedirectUri, "http://www.fabrikam.com/callback");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = null
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'redirect_uri' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenRedirectUriIsInvalid()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Private.RedirectUri, "http://www.fabrikam.com/callback");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.contoso.com/redirect_uri"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified 'redirect_uri' parameter doesn't match the client " +
                         "redirection endpoint the authorization code was initially sent to.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenCodeVerifierIsMissing()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Private.CodeChallenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                            .SetClaim(Claims.Private.CodeChallengeMethod, CodeChallengeMethods.Sha256);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                CodeVerifier = null,
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'code_verifier' parameter is missing.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(CodeChallengeMethods.Plain, "challenge", "invalid_verifier")]
        [InlineData(CodeChallengeMethods.Sha256, "challenge", "invalid_verifier")]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenCodeVerifierIsInvalid(string method, string challenge, string verifier)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Private.CodeChallenge, challenge)
                            .SetClaim(Claims.Private.CodeChallengeMethod, method);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                CodeVerifier = verifier,
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified 'code_verifier' parameter is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(CodeChallengeMethods.Plain, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")]
        [InlineData(CodeChallengeMethods.Sha256, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")]
        public async Task ValidateTokenRequest_TokenRequestSucceedsWhenCodeVerifierIsValid(string method, string challenge, string verifier)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Private.CodeChallenge, challenge)
                            .SetClaim(Claims.Private.CodeChallengeMethod, method);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                CodeVerifier = verifier,
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenScopeIsUnexpected()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetScopes(Enumerable.Empty<string>());

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                Scope = "profile phone"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The 'scope' parameter is not valid in this context.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_AuthorizationCodeCausesAnErrorWhenScopeIsInvalid()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetScopes("profile", "email");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                Scope = "profile phone"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified 'scope' parameter is invalid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RefreshTokenCausesAnErrorWhenScopeIsUnexpected()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetScopes(Enumerable.Empty<string>());

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                Scope = "profile phone"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The 'scope' parameter is not valid in this context.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RefreshTokenCausesAnErrorWhenScopeIsInvalid()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetScopes("profile", "email");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                Scope = "profile phone"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified 'scope' parameter is invalid.", response.ErrorDescription);
        }

        [Theory]
        [InlineData(GrantTypes.AuthorizationCode)]
        [InlineData(GrantTypes.ClientCredentials)]
        [InlineData(GrantTypes.Password)]
        [InlineData(GrantTypes.RefreshToken)]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenFlowIsNotEnabled(string flow)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.Configure(options => options.GrantTypes.Remove(flow));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = flow,
                Username = "johndoe",
                Password = "A3ddj3w",
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.UnsupportedGrantType, response.Error);
            Assert.Equal("The specified 'grant_type' parameter is not supported.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.Configure(options => options.GrantTypes.Remove(GrantTypes.RefreshToken));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'offline_access' scope is not allowed.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenUnregisteredScopeIsSpecified()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(CreateScopeManager(mock =>
                {
                    mock.Setup(manager => manager.FindByNamesAsync(
                        It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "unregistered_scope"),
                        It.IsAny<CancellationToken>()))
                        .Returns(AsyncEnumerable.Empty<OpenIddictScope>());
                }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "unregistered_scope"
            });

            // Assert
            Assert.Equal(Errors.InvalidScope, response.Error);
            Assert.Equal("The specified 'scope' parameter is not valid.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsValidatedWhenScopeRegisteredInOptionsIsSpecified()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.RegisterScopes("registered_scope");
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
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

            var manager = CreateScopeManager(mock =>
            {
                mock.Setup(manager => manager.FindByNamesAsync(
                    It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "scope_registered_in_database"),
                    It.IsAny<CancellationToken>()))
                    .Returns(new[] { scope }.ToAsyncEnumerable());

                mock.Setup(manager => manager.GetNameAsync(scope, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("scope_registered_in_database");
            });

            var client = CreateClient(options =>
            {
                options.RegisterScopes("scope_registered_in_options");

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
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

        [Theory]
        [InlineData("client_id", "")]
        [InlineData("", "client_secret")]
        public async Task ValidateTokenRequest_ClientCredentialsRequestIsRejectedWhenCredentialsAreMissing(string identifier, string secret)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = identifier,
                ClientSecret = secret,
                GrantType = GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'client_id' and 'client_secret' parameters are " +
                         "required when using the client credentials grant.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithoutClientIdIsRejectedWhenClientIdentificationIsRequired()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.Configure(options => options.AcceptAnonymousClients = false);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = null,
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The mandatory 'client_id' parameter is missing.", response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenClientCannotBeFound()
        {
            // Arrange
            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal("The specified 'client_id' parameter is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.Endpoints.Token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);

                options.Configure(options => options.IgnoreEndpointPermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the token endpoint.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.Token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenGrantTypePermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.GrantTypes.Password, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);

                options.Configure(options => options.IgnoreGrantTypePermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.UnauthorizedClient, response.Error);
            Assert.Equal("This client application is not allowed to use the specified grant type.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.Password, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.GrantTypes.Password, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);

                options.Configure(options => options.IgnoreGrantTypePermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = Scopes.OfflineAccess
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The client application is not allowed to use the 'offline_access' scope.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientCredentialsRequestFromPublicClientIsRejected()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ClientTypes.Public);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = GrantTypes.ClientCredentials
            });

            // Assert
            Assert.Equal(Errors.UnauthorizedClient, response.Error);
            Assert.Equal("The specified 'grant_type' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenScopePermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ClientTypes.Public);

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);

                options.RegisterScopes(Scopes.Email, Scopes.Profile);
                options.Configure(options => options.IgnoreScopePermissions = false);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "openid offline_access profile email"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("This client application is not allowed to use the specified scope.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.OpenId, It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.OfflineAccess, It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretCannotBeUsedByPublicClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ClientTypes.Public);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal("The 'client_secret' parameter is not valid for this client application.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretIsRequiredForConfidentialClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ClientTypes.Confidential);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = null,
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal("The 'client_secret' parameter required for this client application is missing.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_ClientSecretIsRequiredForHybridClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ClientTypes.Hybrid);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = null,
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal("The 'client_secret' parameter required for this client application is missing.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateTokenRequest_RequestIsRejectedWhenClientCredentialsAreInvalid()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ClientTypes.Confidential);

                mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal("The specified client credentials are invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_AuthorizationCodeRevocationIsIgnoredWhenTokenStorageIsDisabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.SetRevocationEndpointUris(Array.Empty<Uri>());
                options.DisableTokenStorage();
                options.DisableSlidingExpiration();
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleTokenRequest_RefreshTokenRevocationIsIgnoredWhenTokenStorageIsDisabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.SetRevocationEndpointUris(Array.Empty<Uri>());
                options.DisableTokenStorage();
                options.DisableSlidingExpiration();
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationCodeIsUnknown()
        {
            // Arrange
            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenRefreshTokenIsUnknown()
        {
            // Arrange
            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is invalid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationCodeIsAlreadyRedeemed()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenRefreshTokenIsAlreadyRedeemed()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesAuthorizationWhenAuthorizationCodeIsAlreadyRedeemed()
        {
            // Arrange
            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .Returns(AsyncEnumerable.Empty<OpenIddictToken>());
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesAuthorizationWhenRefreshTokenIsAlreadyRedeemed()
        {
            // Arrange
            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .Returns(AsyncEnumerable.Empty<OpenIddictToken>());
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(authorization, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesTokensWhenAuthorizationCodeIsAlreadyRedeemed()
        {
            // Arrange
            var tokens = ImmutableArray.Create(
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken());

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                mock.Setup(manager => manager.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("47468A64-C9A7-49C7-939C-19CC0F5DD166");

                mock.Setup(manager => manager.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8");

                mock.Setup(manager => manager.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                mock.Setup(manager => manager.HasStatusAsync(tokens[0], Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .Returns(tokens.ToAsyncEnumerable());
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(tokens[0], Statuses.Redeemed, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RevokesTokensWhenRefreshTokenIsAlreadyRedeemed()
        {
            // Arrange
            var tokens = ImmutableArray.Create(
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken());

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                mock.Setup(manager => manager.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("47468A64-C9A7-49C7-939C-19CC0F5DD166");

                mock.Setup(manager => manager.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8");

                mock.Setup(manager => manager.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                mock.Setup(manager => manager.HasStatusAsync(tokens[0], Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .Returns(tokens.ToAsyncEnumerable());
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token has already been redeemed.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(tokens[0], Statuses.Redeemed, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationCodeIsInvalid()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenRefreshTokenIsInvalid()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The specified refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_AuthorizationAssociatedWithCodeIsIgnoredWhenAuthorizationStorageIsDisabled()
        {
            // Arrange
            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                    mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                options.Services.AddSingleton(manager);

                options.DisableAuthorizationStorage();
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleTokenRequest_AuthorizationAssociatedWithRefreshTokenIsIgnoredWhenAuthorizationStorageIsDisabled()
        {
            // Arrange
            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
            });
            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);

                options.DisableAuthorizationStorage();
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithAuthorizationCodeCannotBeFound()
        {
            // Arrange
            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithAuthorizationCodeIsInvalid()
        {
            // Arrange
            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);

                mock.Setup(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Public);
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "SplxlOBeZQQYbYS6WxSbIA",
                GrantType = GrantTypes.AuthorizationCode,
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the authorization code is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithRefreshTokenCannotBeFound()
        {
            // Arrange
            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleTokenRequest_RequestIsRejectedWhenAuthorizationAssociatedWithRefreshTokenIsInvalid()
        {
            // Arrange
            var authorization = new OpenIddictAuthorization();

            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(authorization);

                mock.Setup(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(false);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The authorization associated with the refresh token is no longer valid.", response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData(GrantTypes.AuthorizationCode)]
        [InlineData(GrantTypes.ClientCredentials)]
        [InlineData(GrantTypes.Password)]
        [InlineData(GrantTypes.RefreshToken)]
        [InlineData("urn:ietf:params:oauth:grant-type:custom_grant")]
        public async Task HandleTokenRequest_RequestsAreSuccessfullyHandled(string flow)
        {
            // Arrange
            var manager = CreateTokenManager(mock =>
            {
                var token = new OpenIddictToken();

                mock.Setup(manager => manager.FindByIdAsync("0270F515-C5B1-4FBF-B673-D7CAF7CCDABC", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("0270F515-C5B1-4FBF-B673-D7CAF7CCDABC");

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            var client = CreateClient(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Bricoleur")
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("0270F515-C5B1-4FBF-B673-D7CAF7CCDABC");

                        if (context.Request.IsAuthorizationCodeGrantType())
                        {
                            context.Principal.SetPresenters("Fabrikam");
                        }

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.GetClientTypeAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(ClientTypes.Confidential);

                    mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                options.Services.AddSingleton(manager);

                options.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");
                options.DisableAuthorizationStorage();
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
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

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task HandleTokenRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidGrant, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task HandleTokenRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Bricoleur"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task HandleTokenRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyTokenResponse_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyTokenResponseContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Transaction.SetProperty("custom_response", new
                        {
                            name = "Bob le Bricoleur"
                        });

                        context.HandleRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyTokenResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyTokenResponseContext>(builder =>
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
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }
    }
}
