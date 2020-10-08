/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.IntegrationTests
{
    public abstract partial class OpenIddictServerIntegrationTests
    {
        [Theory]
        [InlineData(nameof(HttpMethod.Delete))]
        [InlineData(nameof(HttpMethod.Head))]
        [InlineData(nameof(HttpMethod.Options))]
        [InlineData(nameof(HttpMethod.Put))]
        [InlineData(nameof(HttpMethod.Trace))]
        public async Task ExtractUserinfoRequest_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            await using var server = await CreateServerAsync();
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.SendAsync(method, "/connect/userinfo", new OpenIddictRequest());

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2084), response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ExtractUserinfoRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest());

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ExtractUserinfoRequest_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractUserinfoRequestContext>(builder =>
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

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.GetAsync("/connect/userinfo");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
        }

        [Fact]
        public async Task ExtractUserinfoRequest_AllowsSkippingHandler()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.GetAsync("/connect/userinfo");

            // Assert
            Assert.Equal("Bob le Magnifique", (string?) response["name"]);
        }

        [Fact]
        public async Task ValidateUserinfoRequest_MissingTokenCausesAnError()
        {
            // Arrange
            await using var server = await CreateServerAsync();
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = null
            });

            // Assert
            Assert.Empty(response.GetParameters());
        }

        [Fact]
        public async Task ValidateUserinfoRequest_InvalidTokenCausesAnError()
        {
            // Arrange
            await using var server = await CreateServerAsync();
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2004), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateUserinfoRequest_ExpiredTokenCausesAnError()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetExpirationDate(DateTimeOffset.UtcNow - TimeSpan.FromDays(1));

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID2019), response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ValidateUserinfoRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ValidateUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ValidateUserinfoRequest_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ValidateUserinfoRequestContext>(builder =>
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

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
        }

        [Fact]
        public async Task ValidateUserinfoRequest_AllowsSkippingHandler()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ValidateUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string?) response["name"]);
        }

        [Fact]
        public async Task HandleUserinfoRequest_BasicClaimsAreCorrectlyReturned()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetPresenters("Fabrikam", "Contoso")
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(3, response.Count);
            Assert.Equal("http://localhost/", (string?) response[Claims.Issuer]);
            Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
            Assert.Equal(new[] { "Fabrikam", "Contoso" }, (string[]?) response[Claims.Audience]);
        }

        [Fact]
        public async Task HandleUserinfoRequest_NonBasicClaimsAreNotReturnedWhenNoScopeWasGranted()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        var identity = new ClaimsIdentity("Bearer");
                        identity.AddClaim(Claims.Subject, "Bob le Magnifique");
                        identity.AddClaim(Claims.GivenName, "Bob");
                        identity.AddClaim(Claims.FamilyName, "Saint-Clar");
                        identity.AddClaim(Claims.Birthdate, "04/09/1933");
                        identity.AddClaim(Claims.Email, "bob@le-magnifique.com");
                        identity.AddClaim(Claims.PhoneNumber, "0148962355");

                        context.Principal = new ClaimsPrincipal(identity)
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetPresenters("Fabrikam")
                            .SetScopes(ImmutableArray.Create<string>());

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(3, response.Count);
            Assert.Equal("http://localhost/", (string?) response[Claims.Issuer]);
            Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
            Assert.Equal("Fabrikam", (string?) response[Claims.Audience]);
        }

        [Fact]
        public async Task HandleUserinfoRequest_ProfileClaimsAreCorrectlyReturned()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        var identity = new ClaimsIdentity("Bearer");
                        identity.AddClaim(Claims.Subject, "Bob le Magnifique");
                        identity.AddClaim(Claims.GivenName, "Bob");
                        identity.AddClaim(Claims.FamilyName, "Saint-Clar");
                        identity.AddClaim(Claims.Birthdate, "04/09/1933");

                        context.Principal = new ClaimsPrincipal(identity)
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetPresenters("Fabrikam")
                            .SetScopes(Scopes.Profile)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob", (string?) response[Claims.GivenName]);
            Assert.Equal("Saint-Clar", (string?) response[Claims.FamilyName]);
            Assert.Equal("04/09/1933", (string?) response[Claims.Birthdate]);
        }

        [Fact]
        public async Task HandleUserinfoRequest_EmailClaimIsCorrectlyReturned()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetPresenters("Fabrikam")
                            .SetScopes(Scopes.Email)
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetClaim(Claims.Email, "bob@le-magnifique.com");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("bob@le-magnifique.com", (string?) response[Claims.Email]);
        }

        [Fact]
        public async Task HandleUserinfoRequest_PhoneClaimIsCorrectlyReturned()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetPresenters("Fabrikam")
                            .SetScopes(Scopes.Phone)
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetClaim(Claims.PhoneNumber, "0148962355");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("0148962355", (string?) response[Claims.PhoneNumber]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task HandleUserinfoRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task HandleUserinfoRequest_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<HandleUserinfoRequestContext>(builder =>
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

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
        }

        [Fact]
        public async Task HandleUserinfoRequest_AllowsSkippingHandler()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

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

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string?) response["name"]);
        }

        [Fact]
        public async Task ApplyUserinfoResponse_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ApplyUserinfoResponseContext>(builder =>
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

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
        }

        [Fact]
        public async Task ApplyUserinfoResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("SlAV32hkKG", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ApplyUserinfoResponseContext>(builder =>
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

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/userinfo", new OpenIddictRequest
            {
                AccessToken = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("custom_value", (string?) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]?) response["parameter_with_multiple_values"]);
        }
    }
}
