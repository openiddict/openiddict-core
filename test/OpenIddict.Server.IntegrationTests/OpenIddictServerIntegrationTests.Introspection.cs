/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Introspection;
using SR = OpenIddict.Abstractions.OpenIddictResources;

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
        public async Task ExtractIntrospectionRequest_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.SendAsync(method, "/connect/introspect", new OpenIddictRequest());

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3084), response.ErrorDescription);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ExtractIntrospectionRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest());

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ExtractIntrospectionRequest_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractIntrospectionRequestContext>(builder =>
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
            var response = await client.GetAsync("/connect/introspect");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ExtractIntrospectionRequest_AllowsSkippingHandler()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.GetAsync("/connect/introspect");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_MissingTokenCausesAnError()
        {
            // Arrange
            await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = null
            });

            // Assert
            Assert.Equal(Errors.InvalidRequest, response.Error);
            Assert.Equal(SR.FormatID3029(Parameters.Token), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_InvalidTokenCausesAnError()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3004), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_ExpiredTokenCausesAnError()
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
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetExpirationDate(DateTimeOffset.UtcNow - TimeSpan.FromDays(1));

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "SlAV32hkKG",
                TokenTypeHint = TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3019), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_AuthorizationCodeCausesAnErrorWhenPresentersAreMissing()
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
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters(Enumerable.Empty<string>());

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.PostAsync("/connect/introspect", new OpenIddictRequest
                {
                    ClientId = "Fabrikam",
                    Token = "SlAV32hkKG",
                    TokenTypeHint = TokenTypeHints.AuthorizationCode
                });
            });

            Assert.Equal(SR.GetResourceString(SR.ID1042), exception.Message);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_AuthorizationCodeCausesAnErrorWhenCallerIsNotAValidPresenter()
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
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Contoso");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Token = "SlAV32hkKG",
                TokenTypeHint = TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3077), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_AccessTokenCausesAnErrorWhenCallerIsNotAValidAudienceOrPresenter()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetAudiences("AdventureWorks")
                            .SetPresenters("Contoso");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3077), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_IdentityTokenCausesAnErrorWhenCallerIsNotAValidAudience()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.IdToken)
                            .SetAudiences("AdventureWorks");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.IdToken
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3077), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RefreshTokenCausesAnErrorWhenCallerIsNotAValidPresenter()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("8xLOxBtZp8", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetPresenters("Contoso");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Token = "8xLOxBtZp8",
                TokenTypeHint = TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3077), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestWithoutClientIdIsRejectedWhenClientIdentificationIsRequired()
        {
            // Arrange
            await using var server = await CreateServerAsync(builder =>
            {
                builder.Configure(options => options.AcceptAnonymousClients = false);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal(SR.FormatID3029(Parameters.ClientId), response.ErrorDescription);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestIsRejectedWhenClientCannotBeFound()
        {
            // Arrange
            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal(SR.FormatID3052(Parameters.ClientId), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasPermissionAsync(application,
                    Permissions.Endpoints.Introspection, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.Services.AddSingleton(manager);

                options.Configure(options => options.IgnoreEndpointPermissions = false);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(Errors.UnauthorizedClient, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3075), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.Introspection, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_ClientSecretCannotBeUsedByPublicClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            await using var server = await CreateServerAsync(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal(SR.FormatID3061(Parameters.ClientSecret), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_ClientSecretIsRequiredForNonPublicClients()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            await using var server = await CreateServerAsync(builder =>
            {
                builder.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = null,
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(Errors.InvalidClient, response.Error);
            Assert.Equal(SR.FormatID3062(Parameters.ClientSecret), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_RequestIsRejectedWhenClientCredentialsAreInvalid()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);

                mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert

            Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()), Times.AtLeastOnce());
            Mock.Get(manager).Verify(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ValidateIntrospectionRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
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
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateIntrospectionRequest_AllowsSkippingHandler()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ValidateIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_BasicClaimsAreCorrectlyReturned()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetAudiences("Fabrikam")
                            .SetPresenters("Contoso", "AdventureWorks Cycles")
                            .SetCreationDate(new DateTimeOffset(2016, 1, 1, 0, 0, 0, TimeSpan.Zero))
                            .SetExpirationDate(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero))
                            .SetClaim(Claims.Subject, "Bob le Magnifique")
                            .SetClaim(Claims.JwtId, "66B65AED-4033-4E9C-B975-A8CA7FB6FA79");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.RemoveEventHandler(ValidateExpirationDate.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(11, response.Count);
            Assert.True((bool) response[Claims.Active]);
            Assert.Equal("66B65AED-4033-4E9C-B975-A8CA7FB6FA79", (string) response[Claims.JwtId]);
            Assert.Equal(TokenTypes.Bearer, (string) response[Claims.TokenType]);
            Assert.Equal(TokenTypeHints.AccessToken, (string) response[Claims.TokenUsage]);
            Assert.Equal("http://localhost/", (string) response[Claims.Issuer]);
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);
            Assert.Equal(1451606400, (long) response[Claims.IssuedAt]);
            Assert.Equal(1451606400, (long) response[Claims.NotBefore]);
            Assert.Equal(1483228800, (long) response[Claims.ExpiresAt]);
            Assert.Equal("Fabrikam", (string) response[Claims.Audience]);
            Assert.Equal("Contoso", (string) response[Claims.ClientId]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_NonBasicAuthorizationCodeClaimsAreNotReturned()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AuthorizationCode)
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Username, "Bob")
                            .SetClaim("custom_claim", "secret_value");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.AuthorizationCode
            });

            // Assert
            Assert.Null(response["custom_claim"]);
            Assert.Null(response[Claims.Username]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_NonBasicRefreshTokenClaimsAreNotReturned()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.RefreshToken)
                            .SetPresenters("Fabrikam")
                            .SetClaim(Claims.Username, "Bob")
                            .SetClaim("custom_claim", "secret_value");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.RefreshToken
            });

            // Assert
            Assert.Null(response["custom_claim"]);
            Assert.Null(response[Claims.Username]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_NonBasicAccessTokenClaimsAreReturnedToTrustedAudiences()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetAudiences("Fabrikam")
                            .SetPresenters("Contoso", "AdventureWorks Cycles")
                            .SetScopes(Scopes.OpenId, Scopes.Profile)
                            .SetClaim(Claims.Username, "Bob")
                            .SetClaim("custom_claim", "secret_value");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal("secret_value", (string) response["custom_claim"]);
            Assert.Equal("Bob", (string) response[Claims.Username]);
            Assert.Equal("openid profile", (string) response[Claims.Scope]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_NonBasicIdentityClaimsAreReturnedToTrustedAudiences()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.IdToken)
                            .SetAudiences("Fabrikam")
                            .SetClaim(Claims.Username, "Bob")
                            .SetClaim("custom_claim", "secret_value");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.IdToken
            });

            // Assert
            Assert.Equal("secret_value", (string) response["custom_claim"]);
            Assert.Equal("Bob", (string) response[Claims.Username]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_ClaimValueTypesAreHonored()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        var identity = new ClaimsIdentity("Bearer");
                        identity.AddClaim(new Claim("boolean_claim", "true", ClaimValueTypes.Boolean));
                        identity.AddClaim(new Claim("integer_claim", "42", ClaimValueTypes.Integer));
                        identity.AddClaim(new Claim("array_claim", @"[""Contoso"",""Fabrikam""]", JsonClaimValueTypes.JsonArray));
                        identity.AddClaim(new Claim("object_claim", @"{""parameter"":""value""}", JsonClaimValueTypes.Json));

                        context.Principal = new ClaimsPrincipal(identity)
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetAudiences("Fabrikam");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.AccessToken
            });

            // Assert
            Assert.True((bool) response["boolean_claim"]);
            Assert.Equal(JsonValueKind.True, ((JsonElement) response["boolean_claim"]).ValueKind);
            Assert.Equal(42, (long) response["integer_claim"]);
            Assert.Equal(JsonValueKind.Number, ((JsonElement) response["integer_claim"]).ValueKind);
            Assert.Equal(new[] { "Contoso", "Fabrikam" }, (string[]) response["array_claim"]);
            Assert.Equal(JsonValueKind.Array, ((JsonElement) response["array_claim"]).ValueKind);
            Assert.Equal("value", (string) response["object_claim"]?["parameter"]);
            Assert.Equal(JsonValueKind.Object, ((JsonElement) response["object_claim"]).ValueKind);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_MultipleClaimsAreReturnedAsArrays()
        {
            // Arrange
            var application = new OpenIddictApplication();

            var manager = CreateApplicationManager(mock =>
            {
                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        var identity = new ClaimsIdentity("Bearer");
                        identity.AddClaim(new Claim("boolean_claim", "true", ClaimValueTypes.Boolean));
                        identity.AddClaim(new Claim("boolean_claim", "false", ClaimValueTypes.Boolean));

                        identity.AddClaim(new Claim("integer_claim", "42", ClaimValueTypes.Integer));
                        identity.AddClaim(new Claim("integer_claim", "43", ClaimValueTypes.Integer));

                        identity.AddClaim(new Claim("array_claim", @"[""Contoso"",""Fabrikam""]", JsonClaimValueTypes.JsonArray));
                        identity.AddClaim(new Claim("array_claim", @"[""Microsoft"",""Google""]", JsonClaimValueTypes.JsonArray));

                        identity.AddClaim(new Claim("object_claim", @"{""parameter_1"":""value-1""}", JsonClaimValueTypes.Json));
                        identity.AddClaim(new Claim("object_claim", @"{""parameter_2"":""value-2""}", JsonClaimValueTypes.Json));

                        context.Principal = new ClaimsPrincipal(identity)
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetAudiences("Fabrikam");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(manager);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "2YotnFZFEjr1zCsicMWpAA",
                TokenTypeHint = TokenTypeHints.AccessToken
            });

            // Assert
            Assert.Equal(JsonValueKind.Array, ((JsonElement) response["boolean_claim"]).ValueKind);
            Assert.Equal(2, ((JsonElement) response["boolean_claim"]).GetArrayLength());
            Assert.True(((JsonElement) response["boolean_claim"])[0].GetBoolean());
            Assert.False(((JsonElement) response["boolean_claim"])[1].GetBoolean());

            Assert.Equal(JsonValueKind.Array, ((JsonElement) response["integer_claim"]).ValueKind);
            Assert.Equal(2, ((JsonElement) response["boolean_claim"]).GetArrayLength());
            Assert.Equal(42, ((JsonElement) response["integer_claim"])[0].GetInt64());
            Assert.Equal(43, ((JsonElement) response["integer_claim"])[1].GetInt64());

            Assert.Equal(JsonValueKind.Array, ((JsonElement) response["array_claim"]).ValueKind);
            Assert.Equal(2, ((JsonElement) response["array_claim"]).GetArrayLength());
            Assert.Equal(2, ((JsonElement) response["array_claim"])[0].GetArrayLength());
            Assert.Equal("Contoso", ((JsonElement) response["array_claim"])[0][0].GetString());
            Assert.Equal("Fabrikam", ((JsonElement) response["array_claim"])[0][1].GetString());
            Assert.Equal(2, ((JsonElement) response["array_claim"])[1].GetArrayLength());
            Assert.Equal("Microsoft", ((JsonElement) response["array_claim"])[1][0].GetString());
            Assert.Equal("Google", ((JsonElement) response["array_claim"])[1][1].GetString());

            Assert.Equal(JsonValueKind.Array, ((JsonElement) response["object_claim"]).ValueKind);
            Assert.Equal(2, ((JsonElement) response["object_claim"]).GetArrayLength());
            Assert.Equal("value-1", ((JsonElement) response["object_claim"])[0].GetProperty("parameter_1").GetString());
            Assert.Equal("value-2", ((JsonElement) response["object_claim"])[1].GetProperty("parameter_2").GetString());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenReferenceTokenIsUnknown()
        {
            // Arrange
            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                options.Services.AddSingleton(manager);

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3004), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_AuthorizationIsIgnoredWhenAuthorizationStorageIsDisabled()
        {
            // Arrange
            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new OpenIddictAuthorization());
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetAudiences("Fabrikam")
                            .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                            .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(TokenTypeHints.AccessToken);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                    mock.Setup(manager => manager.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("2YotnFZFEjr1zCsicMWpAA");

                    mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);

                options.DisableAuthorizationStorage();
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response[Claims.Subject]);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenAuthorizationCannotBeFound()
        {
            // Arrange
            var manager = CreateAuthorizationManager(mock =>
            {
                mock.Setup(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(value: null);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetAudiences("Fabrikam")
                            .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                            .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(TokenTypeHints.AccessToken);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                    mock.Setup(manager => manager.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("2YotnFZFEjr1zCsicMWpAA");

                    mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3023), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenAuthorizationIsInvalid()
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

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetAudiences("Fabrikam")
                            .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                            .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                options.Services.AddSingleton(CreateTokenManager(mock =>
                {
                    var token = new OpenIddictToken();

                    mock.Setup(manager => manager.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(TokenTypeHints.AccessToken);

                    mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                    mock.Setup(manager => manager.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("2YotnFZFEjr1zCsicMWpAA");

                    mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(token);

                    mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.GetAuthorizationIdAsync(token, It.IsAny<CancellationToken>()))
                        .ReturnsAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0");
                }));

                options.Services.AddSingleton(manager);

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3023), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByIdAsync("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(authorization, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task HandleIntrospectionRequest_RequestIsRejectedWhenReferenceTokenIsInvalid()
        {
            // Arrange
            var token = new OpenIddictToken();

            var manager = CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(TokenTypeHints.AccessToken);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.GetPayloadAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("2YotnFZFEjr1zCsicMWpAA");

                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            });

            await using var server = await CreateServerAsync(options =>
            {
                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetAudiences("Fabrikam")
                            .SetAuthorizationId("18D15F73-BE2B-6867-DC01-B3C1E8AFDED0")
                            .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                            .SetTokenType(TokenTypeHints.AccessToken)
                            .SetClaim(Claims.Subject, "Bob le Magnifique");

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.Services.AddSingleton(CreateApplicationManager(mock =>
                {
                    var application = new OpenIddictApplication();

                    mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(application);

                    mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);

                    mock.Setup(manager => manager.ValidateClientSecretAsync(application, "7Fjfp0ZBr1KtDRbnfVdmIw", It.IsAny<CancellationToken>()))
                        .ReturnsAsync(true);
                }));

                options.Services.AddSingleton(manager);

                options.RemoveEventHandler(NormalizeErrorResponse.Descriptor);
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
                Token = "QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI"
            });

            // Assert
            Assert.Equal(Errors.InvalidToken, response.Error);
            Assert.Equal(SR.GetResourceString(SR.ID3019), response.ErrorDescription);

            Mock.Get(manager).Verify(manager => manager.FindByReferenceIdAsync("QaTk2f6UPe9trKismGBJr0OIs0KqpvNrqRsJqGuJAAI", It.IsAny<CancellationToken>()), Times.Once());
            Mock.Get(manager).Verify(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()), Times.Once());
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task HandleIntrospectionRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<HandleIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<HandleIntrospectionRequestContext>(builder =>
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
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task HandleIntrospectionRequest_AllowsSkippingHandler()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<HandleIntrospectionRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            await using var client = await server.CreateClientAsync();

            // Act
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyIntrospectionResponse_AllowsHandlingResponse()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                {
                    builder.UseInlineHandler(context =>
                    {
                        Assert.Equal("2YotnFZFEjr1zCsicMWpAA", context.Token);

                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                            .SetTokenType(TokenTypeHints.AccessToken);

                        return default;
                    });

                    builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
                });

                options.AddEventHandler<ApplyIntrospectionResponseContext>(builder =>
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
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "2YotnFZFEjr1zCsicMWpAA"
            });

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyIntrospectionResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            await using var server = await CreateServerAsync(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyIntrospectionResponseContext>(builder =>
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
            var response = await client.PostAsync("/connect/introspect", new OpenIddictRequest
            {
                Token = "SlAV32hkKG"
            });

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }
    }
}
