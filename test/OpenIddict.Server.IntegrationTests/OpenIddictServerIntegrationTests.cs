/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace OpenIddict.Server.FunctionalTests
{
    public abstract partial class OpenIddictServerIntegrationTests
    {
        [Fact]
        public async Task ProcessAuthentication_UnknownEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/authenticate", new OpenIddictRequest());
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("An identity cannot be extracted from this request.")
                .Append("This generally indicates that the OpenIddict server stack was asked ")
                .AppendLine("to validate a token for an endpoint it doesn't manage.")
                .Append("To validate tokens received by custom API endpoints, ")
                .Append("the OpenIddict validation services must be used instead.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessAuthentication_InvalidEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetConfigurationEndpointUris("/authenticate");

                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/authenticate");
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("An identity cannot be extracted from this request.")
                .Append("This generally indicates that the OpenIddict server stack was asked ")
                .AppendLine("to validate a token for an endpoint it doesn't manage.")
                .Append("To validate tokens received by custom API endpoints, ")
                .Append("the OpenIddict validation services must be used instead.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessAuthentication_UnsupportedGrantTypeThrowsAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/authenticate");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/authenticate", new OpenIddictRequest
                {
                    GrantType = GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w",
                });
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("An identity cannot be extracted from this token request.")
                .Append("This generally indicates that the OpenIddict server stack was asked ")
                .AppendLine("to validate a token for an invalid grant type (e.g password).")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessAuthentication_MissingAccessTokenReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetLogoutEndpointUris("/authenticate");

                options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                AccessToken = null
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_InvalidAccessTokenReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetLogoutEndpointUris("/authenticate");

                options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                AccessToken = "38323A4B-6CB2-41B8-B457-1951987CB383"
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_ValidAccessTokenReturnsExpectedIdentity()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetUserinfoEndpointUris("/authenticate");

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("access_token", context.Token);
                        Assert.Equal(TokenTypeHints.AccessToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                AccessToken = "access_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_AuthorizedPartyIsMappedToPresenter()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetUserinfoEndpointUris("/authenticate");

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("access_token", context.Token);
                        Assert.Equal(TokenTypeHints.AccessToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetClaim(Claims.AuthorizedParty, "Fabrikam");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                AccessToken = "access_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
            Assert.Equal("Fabrikam", (string) response[Claims.AuthorizedParty]);
            Assert.Equal("Fabrikam", (string) response[Claims.Private.Presenter]);
        }

        [Fact]
        public async Task ProcessAuthentication_SinglePublicScopeIsMappedToPrivateClaims()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetUserinfoEndpointUris("/authenticate");

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("access_token", context.Token);
                        Assert.Equal(TokenTypeHints.AccessToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetClaim(Claims.Scope, "openid profile");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                AccessToken = "access_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
            Assert.Equal("openid profile", (string) response[Claims.Scope]);
            Assert.Equal(new[] { Scopes.OpenId, Scopes.Profile }, (string[]) response[Claims.Private.Scope]);
        }

        [Fact]
        public async Task ProcessAuthentication_MultiplePublicScopesAreMappedToPrivateClaims()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetUserinfoEndpointUris("/authenticate");

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("access_token", context.Token);
                        Assert.Equal(TokenTypeHints.AccessToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetClaims(Claims.Scope, ImmutableArray.Create(Scopes.OpenId, Scopes.Profile));

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                AccessToken = "access_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
            Assert.Equal(new[] { Scopes.OpenId, Scopes.Profile }, (string[]) response[Claims.Scope]);
            Assert.Equal(new[] { Scopes.OpenId, Scopes.Profile }, (string[]) response[Claims.Private.Scope]);
        }

        [Fact]
        public async Task ProcessAuthentication_MissingTokenTypeThrowsAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetUserinfoEndpointUris("/authenticate");

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("access_token", context.Token);
                        Assert.Equal(TokenTypeHints.AccessToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(null)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/authenticate", new OpenIddictRequest
                {
                    AccessToken = "access_token"
                });
            });

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendLine("The deserialized principal doesn't contain the mandatory 'oi_tkn_typ' claim.")
                .Append("When implementing custom token deserialization, a 'oi_tkn_typ' claim containing ")
                .Append("the type of the token being processed must be added to the security principal.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessAuthentication_InvalidTokenTypeThrowsAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetUserinfoEndpointUris("/authenticate");

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("access_token", context.Token);
                        Assert.Equal(TokenTypeHints.AccessToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/authenticate", new OpenIddictRequest
                {
                    AccessToken = "access_token"
                });
            });

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendFormat("The type of token associated with the deserialized principal ({0}) ", TokenTypeHints.AuthorizationCode)
                .AppendFormat("doesn't match the expected token type ({0}).", TokenTypeHints.AccessToken)
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessAuthentication_MissingIdTokenHintReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetLogoutEndpointUris("/authenticate");

                options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                IdTokenHint = null
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_InvalidIdTokenHintReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetLogoutEndpointUris("/authenticate");

                options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                IdTokenHint = "38323A4B-6CB2-41B8-B457-1951987CB383"
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_ValidIdTokenHintReturnsExpectedIdentity()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetLogoutEndpointUris("/authenticate");

                options.AddEventHandler<HandleLogoutRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("id_token", context.Token);
                        Assert.Equal(TokenTypeHints.IdToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.IdToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.GetAsync("/authenticate", new OpenIddictRequest
            {
                IdTokenHint = "id_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_MissingAuthorizationCodeReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/authenticate");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/authenticate", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = null,
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_InvalidAuthorizationCodeReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/authenticate");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/authenticate", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "38323A4B-6CB2-41B8-B457-1951987CB383",
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_ValidAuthorizationCodeReturnsExpectedIdentity()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/authenticate");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("authorization_code", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetPresenters("Fabrikam");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/authenticate", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Code = "authorization_code",
                GrantType = GrantTypes.AuthorizationCode
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_MissingRefreshTokenReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/authenticate");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/authenticate", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = null
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_InvalidRefreshTokenReturnsNull()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/authenticate");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/authenticate", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "38323A4B-6CB2-41B8-B457-1951987CB383"
            });

            // Assert
            Assert.Null((string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessAuthentication_ValidRefreshTokenReturnsExpectedIdentity()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/authenticate");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("refresh_token", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            // Act
            var response = await client.PostAsync("/authenticate", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "refresh_token"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
        }

        [Fact]
        public async Task ProcessChallenge_UnknownEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/challenge", new OpenIddictRequest());
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task ProcessChallenge_InvalidEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetConfigurationEndpointUris("/challenge");

                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/challenge");
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task ProcessChallenge_ReturnsDefaultErrorForAuthorizationRequestsWhenNoneIsSpecified()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetAuthorizationEndpointUris("/challenge");

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/challenge", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Nonce = "n-0S6_WzA2Mj",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.Equal(Errors.AccessDenied, response.Error);
            Assert.Equal("The authorization was denied by the resource owner.", response.ErrorDescription);
            Assert.Null(response.ErrorUri);
        }

        [Fact]
        public async Task ProcessChallenge_ReturnsDefaultErrorForTokenRequestsWhenNoneIsSpecified()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/challenge");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/challenge", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal(Errors.InvalidGrant, response.Error);
            Assert.Equal("The token request was rejected by the authorization server.", response.ErrorDescription);
            Assert.Null(response.ErrorUri);
        }

        [Fact]
        public async Task ProcessChallenge_ReturnsDefaultErrorForUserinfoRequestsWhenNoneIsSpecified()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetUserinfoEndpointUris("/challenge");

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/challenge", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(Errors.InsufficientAccess, response.Error);
            Assert.Equal("The user information access demand was rejected by the authorization server.", response.ErrorDescription);
            Assert.Null(response.ErrorUri);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ProcessChallenge_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/challenge");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessChallengeContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/challenge", new OpenIddictRequest
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
        public async Task ProcessChallenge_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetTokenEndpointUris("/challenge");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));

                options.AddEventHandler<ProcessChallengeContext>(builder =>
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
            var response = await client.PostAsync("/challenge", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ProcessSignIn_UnknownEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/signin", new OpenIddictRequest());
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task ProcessSignIn_InvalidEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetConfigurationEndpointUris("/signin");

                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/signin");
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task ProcessSignIn_NullIdentityCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal();

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/connect/token", new OpenIddictRequest
                {
                    GrantType = GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w"
                });
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified principal doesn't contain any claims-based identity.")
                .Append("Make sure that both 'ClaimsPrincipal.Identity' is not null.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessSignIn_NullAuthenticationTypeCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/connect/token", new OpenIddictRequest
                {
                    GrantType = GrantTypes.Password,
                    Username = "johndoe",
                    Password = "A3ddj3w"
                });
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The specified principal doesn't contain a valid/authenticated identity.")
                .Append("Make sure that 'ClaimsPrincipal.Identity.AuthenticationType' is not null ")
                .Append("and that 'ClaimsPrincipal.Identity.IsAuthenticated' returns 'true'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task ProcessSignIn_MissingSubjectCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"));

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

            Assert.Equal("The specified principal was rejected because the mandatory subject claim was missing.", exception.Message);
        }

        [Fact]
        public async Task ProcessSignIn_ScopeDefaultsToOpenId()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal(new[] { Scopes.OpenId }, context.Principal.GetScopes());

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ProcessSignIn_ResourcesAreInferredFromAudiences()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetAudiences("http://www.fabrikam.com/")
                            .SetScopes(Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal(new[] { "http://www.fabrikam.com/" }, context.Principal.GetResources());

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
            Assert.NotNull(response.AccessToken);
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_AllowsOverridingDefaultTokensSelection()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        context.IncludeAccessToken = false;
                        context.IncludeAuthorizationCode = true;
                        context.IncludeIdentityToken = true;
                        context.IncludeRefreshToken = true;

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Null(response.AccessToken);
            Assert.NotNull(response.Code);
            Assert.NotNull(response.IdToken);
            Assert.NotNull(response.RefreshToken);
        }

        [Theory]
        [InlineData("code")]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        public async Task ProcessSignIn_AnAuthorizationCodeIsReturnedForCodeAndHybridFlowRequests(string type)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeAuthorizationCode);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
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
            Assert.NotNull(response.Code);
        }

        [Fact]
        public async Task ProcessSignIn_ScopesCanBeOverridenForRefreshTokenRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.RegisterScopes(Scopes.Profile);

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.Profile, Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal(new[] { Scopes.Profile }, context.AccessTokenPrincipal.GetScopes());

                        return default;
                    });

                    builder.SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8",
                Scope = Scopes.Profile
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ProcessSignIn_ScopesAreReturnedWhenTheyDifferFromRequestedScopes()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.RegisterScopes(Scopes.Phone, Scopes.Profile);

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetScopes(Scopes.Profile)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = "openid phone profile"
            });

            // Assert
            Assert.Equal(Scopes.Profile, response.Scope);
        }

        [Theory]
        [InlineData("code id_token token")]
        [InlineData("code token")]
        [InlineData("id_token token")]
        [InlineData("token")]
        public async Task ProcessSignIn_AnAccessTokenIsReturnedForImplicitAndHybridFlowRequests(string type)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeAccessToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
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
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnAccessTokenIsReturnedForCodeGrantRequests()
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
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeAccessToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
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
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnAccessTokenIsReturnedForRefreshTokenGrantRequests()
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeAccessToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
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
        public async Task ProcessSignIn_AnAccessTokenIsReturnedForPasswordGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeAccessToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnAccessTokenIsReturnedForClientCredentialsGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeAccessToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = GrantTypes.ClientCredentials,
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnAccessTokenIsReturnedForCustomGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeAccessToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = "urn:ietf:params:oauth:grant-type:custom_grant"
            });

            // Assert
            Assert.NotNull(response.AccessToken);
        }

        [Fact]
        public async Task ProcessSignIn_ExpiresInIsReturnedWhenExpirationDateIsKnown()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

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
            Assert.NotNull(response.ExpiresIn);
        }

        [Fact]
        public async Task ProcessSignIn_NoRefreshTokenIsReturnedWhenOfflineAccessScopeIsNotGranted()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.False(context.IncludeRefreshToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_ARefreshTokenIsReturnedForCodeGrantRequests()
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
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Fabrikam")
                            .SetScopes(Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeRefreshToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
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
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_NoRefreshTokenIsReturnedForRefreshTokenGrantRequests()
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.False(context.IncludeRefreshToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_NoRefreshTokenIsReturnedWhenSlidingExpirationIsDisabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.DisableSlidingExpiration();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.False(context.IncludeRefreshToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_ARefreshTokenIsReturnedForPasswordGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeRefreshToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetScopes(Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

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
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_ARefreshTokenIsReturnedForClientCredentialsGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeRefreshToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetScopes(Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = GrantTypes.ClientCredentials,
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_ARefreshTokenIsReturnedForCustomGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeRefreshToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetScopes(Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = "urn:ietf:params:oauth:grant-type:custom_grant"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_NoIdentityTokenIsReturnedWhenOfflineAccessScopeIsNotGranted()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.False(context.IncludeIdentityToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });

            // Assert
            Assert.Null(response.IdToken);
        }

        [Theory]
        [InlineData("code id_token")]
        [InlineData("code id_token token")]
        [InlineData("id_token")]
        [InlineData("id_token token")]
        public async Task ProcessSignIn_AnIdentityTokenIsReturnedForImplicitAndHybridFlowRequests(string type)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeIdentityToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
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
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnIdentityTokenIsReturnedForCodeGrantRequests()
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
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Fabrikam")
                            .SetScopes(Scopes.OpenId)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeIdentityToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
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
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnIdentityTokenIsReturnedForRefreshTokenGrantRequests()
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeIdentityToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnIdentityTokenIsReturnedForPasswordGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeIdentityToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w",
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnIdentityTokenIsReturnedForClientCredentialsGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeIdentityToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                GrantType = GrantTypes.ClientCredentials,
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Fact]
        public async Task ProcessSignIn_AnIdentityTokenIsReturnedForCustomGrantRequests()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.True(context.IncludeIdentityToken);

                        return default;
                    });

                    builder.SetOrder(EvaluateReturnedTokens.Descriptor.Order + 500);
                });
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = "urn:ietf:params:oauth:grant-type:custom_grant",
                Scope = Scopes.OpenId
            });

            // Assert
            Assert.NotNull(response.IdToken);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ProcessSignIn_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
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
        public async Task ProcessSignIn_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));

                options.AddEventHandler<ProcessSignInContext>(builder =>
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
        public async Task ProcessSignIn_PrivateClaimsAreAutomaticallyRestored()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.UseRollingTokens();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur")
                            .SetClaim(Claims.Prefixes.Private + "_private_claim", "value");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ProcessSignInContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal(new[] { Scopes.OpenId, Scopes.OfflineAccess }, context.Principal.GetScopes());
                        Assert.Equal("value", context.Principal.GetClaim(Claims.Prefixes.Private + "_private_claim"));

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.RefreshToken,
                RefreshToken = "8xLOxBtZp8"
            });

            // Assert
            Assert.NotNull(response.IdToken);
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_RefreshTokenIsIssuedForAuthorizationCodeRequestsWhenRollingTokensAreEnabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.UseRollingTokens();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                        Assert.Equal(TokenTypeHints.AuthorizationCode, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Fabrikam")
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
                RedirectUri = "http://www.fabrikam.com/path"
            });

            // Assert
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_RefreshTokenIsAlwaysIssuedWhenRollingTokensAreEnabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.UseRollingTokens();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.NotNull(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_RefreshTokenIsNotIssuedWhenRollingTokensAreDisabled()
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.Null(response.RefreshToken);
        }

        [Fact]
        public async Task ProcessSignIn_AuthorizationCodeIsAutomaticallyRedeemed()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
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
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
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
            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_ReturnsErrorResponseWhenRedeemingAuthorizationCodeFails()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
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
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Fabrikam")
                            .SetInternalTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
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
            Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_RefreshTokenIsAutomaticallyRedeemedWhenRollingTokensAreEnabled()
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
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
            });

            var client = CreateClient(options =>
            {
                options.UseRollingTokens();
                options.DisableAuthorizationStorage();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_ReturnsErrorResponseWhenRedeemingRefreshTokenFails()
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
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            var client = CreateClient(options =>
            {
                options.UseRollingTokens();
                options.DisableAuthorizationStorage();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_RefreshTokenIsNotRedeemedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSignIn_PreviousTokensAreAutomaticallyRevokedWhenRollingTokensAreEnabled()
        {
            // Arrange
            var tokens = new[]
            {
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken()
            };

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                mock.Setup(manager => manager.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("481FCAC6-06BC-43EE-92DB-37A78AA09B595073CC313103");

                mock.Setup(manager => manager.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8");

                mock.Setup(manager => manager.GetAuthorizationIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");

                mock.Setup(manager => manager.HasStatusAsync(tokens[0], Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(tokens[0], Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.TryRedeemAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .Returns(tokens.ToAsyncEnumerable());

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
            });

            var client = CreateClient(options =>
            {
                options.UseRollingTokens();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateAuthorizationManager(mock =>
                {
                    var authorization = new OpenIddictAuthorization();

                    mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(authorization);

                    mock.Setup(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
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
            Assert.NotNull(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_PreviousTokensAreNotRevokedWhenRollingTokensAreDisabled()
        {
            // Arrange
            var tokens = new[]
            {
                new OpenIddictToken(),
                new OpenIddictToken(),
                new OpenIddictToken()
            };

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(tokens[0]);

                mock.Setup(manager => manager.GetIdAsync(tokens[0], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

                mock.Setup(manager => manager.GetIdAsync(tokens[1], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("481FCAC6-06BC-43EE-92DB-37A78AA09B595073CC313103");

                mock.Setup(manager => manager.GetIdAsync(tokens[2], It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3BEA7A94-5ADA-49AF-9F41-8AB6156E31A8");

                mock.Setup(manager => manager.HasStatusAsync(tokens[0], Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(tokens[0], Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.FindByAuthorizationIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .Returns(tokens.ToAsyncEnumerable());

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateAuthorizationManager(mock =>
                {
                    var authorization = new OpenIddictAuthorization();

                    mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(authorization);

                    mock.Setup(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
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
            Assert.NotNull(response.AccessToken);
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[0], It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[1], It.IsAny<CancellationToken>()), Times.Never());
            Mock.Get(manager).Verify(manager => manager.TryRevokeAsync(tokens[2], It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSignIn_ExtendsLifetimeWhenRollingTokensAreDisabledAndSlidingExpirationEnabled()
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
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.TryExtendAsync(token,
                It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_DoesNotExtendLifetimeWhenSlidingExpirationIsDisabled()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
            });

            var client = CreateClient(options =>
            {
                options.DisableSlidingExpiration();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.TryExtendAsync(token,
                It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSignIn_DoesNotUpdateExpirationDateWhenAlreadyNull()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.TryExtendAsync(token, null, It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSignIn_SetsExpirationDateToNullWhenLifetimeIsNull()
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
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetExpirationDateAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(DateTimeOffset.Now + TimeSpan.FromDays(1));

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
            });

            var client = CreateClient(options =>
            {
                options.SetRefreshTokenLifetime(lifetime: null);

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);
                        Assert.Equal(TokenTypeHints.RefreshToken, context.TokenType);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.Null(response.RefreshToken);

            Mock.Get(manager).Verify(manager => manager.TryExtendAsync(token, null, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_IgnoresErrorWhenExtendingLifetimeOfExistingTokenFailed()
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
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.TryExtendAsync(token, It.IsAny<DateTimeOffset?>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictToken());
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                            .SetInternalTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                            .SetClaim(Claims.Subject, "Bob le Bricoleur");

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
            Assert.NotNull(response.AccessToken);

            Mock.Get(manager).Verify(manager => manager.TryExtendAsync(token,
                It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_AdHocAuthorizationIsAutomaticallyCreated()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());

                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictAuthorizationDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                options.Services.AddSingleton(manager);

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(manager => manager.CreateAsync(
                It.Is<OpenIddictAuthorizationDescriptor>(descriptor =>
                    descriptor.ApplicationId == "3E228451-1555-46F7-A471-951EFBA23A56" &&
                    descriptor.Subject == "Bob le Magnifique" &&
                    descriptor.Type == AuthorizationTypes.AdHoc),
                It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ProcessSignIn_AdHocAuthorizationIsNotCreatedWhenAuthorizationStorageIsDisabled()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
            });

            var client = CreateClient(options =>
            {
                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetIdAsync(application, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");
                }));

                options.Services.AddSingleton(manager);

                options.DisableAuthorizationStorage();

                options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code,
            });

            // Assert
            Assert.NotNull(response.Code);

            Mock.Get(manager).Verify(manager => manager.CreateAsync(It.IsAny<OpenIddictAuthorizationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task ProcessSignOut_UnknownEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/signout", new OpenIddictRequest());
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Fact]
        public async Task ProcessSignOut_InvalidEndpointCausesAnException()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();
                options.SetConfigurationEndpointUris("/signout");

                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/signout");
            });

            Assert.Equal("An OpenID Connect response cannot be returned from this endpoint.", exception.Message);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ProcessSignOut_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessSignOutContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.PostAsync("/connect/logout", new OpenIddictRequest());

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ProcessSignOut_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessSignOutContext>(builder =>
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
            var response = await client.PostAsync("/connect/logout", new OpenIddictRequest());

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        protected virtual void ConfigureServices(IServiceCollection services)
        {
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
                    // Enable the tested endpoints.
                    options.SetAuthorizationEndpointUris("/connect/authorize")
                           .SetConfigurationEndpointUris("/.well-known/openid-configuration")
                           .SetCryptographyEndpointUris("/.well-known/jwks")
                           .SetIntrospectionEndpointUris("/connect/introspect")
                           .SetLogoutEndpointUris("/connect/logout")
                           .SetRevocationEndpointUris("/connect/revoke")
                           .SetTokenEndpointUris("/connect/token")
                           .SetUserinfoEndpointUris("/connect/userinfo");

                    options.AllowAuthorizationCodeFlow()
                           .AllowClientCredentialsFlow()
                           .AllowImplicitFlow()
                           .AllowPasswordFlow()
                           .AllowRefreshTokenFlow();

                    // Accept anonymous clients by default.
                    options.AcceptAnonymousClients();

                    // Disable permission enforcement by default.
                    options.IgnoreEndpointPermissions()
                           .IgnoreGrantTypePermissions()
                           .IgnoreScopePermissions();

                    options.AddSigningCertificate(
                        assembly: typeof(OpenIddictServerIntegrationTests).Assembly,
                        resource: "OpenIddict.Server.IntegrationTests.Certificate.pfx",
                        password: "Owin.Security.OpenIdConnect.Server");

                    options.AddEncryptionCertificate(
                        assembly: typeof(OpenIddictServerIntegrationTests).Assembly,
                        resource: "OpenIddict.Server.IntegrationTests.Certificate.pfx",
                        password: "Owin.Security.OpenIdConnect.Server");

                    options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                        builder.UseInlineHandler(context => default));

                    options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
                        builder.UseInlineHandler(context => default));

                    options.AddEventHandler<ValidateLogoutRequestContext>(builder =>
                        builder.UseInlineHandler(context => default));

                    options.AddEventHandler<ValidateRevocationRequestContext>(builder =>
                        builder.UseInlineHandler(context => default));

                    options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                        builder.UseInlineHandler(context => default));
                });
        }

        protected abstract OpenIddictServerIntegrationTestClient CreateClient(Action<OpenIddictServerBuilder> configuration = null);

        protected OpenIddictApplicationManager<OpenIddictApplication> CreateApplicationManager(
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

        protected OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(
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

        protected OpenIddictScopeManager<OpenIddictScope> CreateScopeManager(
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

        protected OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(
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
