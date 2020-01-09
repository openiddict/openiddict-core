/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
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
        [InlineData(nameof(HttpMethod.Post))]
        [InlineData(nameof(HttpMethod.Put))]
        [InlineData(nameof(HttpMethod.Trace))]
        public async Task ExtractConfigurationRequest_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var client = CreateClient(options => options.EnableDegradedMode());

            // Act
            var response = await client.SendAsync(method, "/.well-known/openid-configuration", new OpenIddictRequest());

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
        public async Task ExtractConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ExtractConfigurationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractConfigurationRequestContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ExtractConfigurationRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ValidateConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ValidateConfigurationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateConfigurationRequestContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateConfigurationRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task HandleConfigurationRequest_IssuerIsAutomaticallyInferred()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal(client.HttpClient.BaseAddress.AbsoluteUri,
                (string) response[Metadata.Issuer]);
        }

        [Fact]
        public async Task HandleConfigurationRequest_RegisteredIssuerIsAlwaysPreferred()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.SetIssuer(new Uri("https://www.fabrikam.com/"));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("https://www.fabrikam.com/",
                (string) response[Metadata.Issuer]);
        }

        [Fact]
        public async Task HandleConfigurationRequest_EnabledEndpointsAreExposed()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.SetIssuer(new Uri("https://www.fabrikam.com/"));

                options.SetAuthorizationEndpointUris("/path/authorization_endpoint")
                       .SetIntrospectionEndpointUris("/path/introspection_endpoint")
                       .SetLogoutEndpointUris("/path/logout_endpoint")
                       .SetRevocationEndpointUris("/path/revocation_endpoint")
                       .SetTokenEndpointUris("/path/token_endpoint")
                       .SetUserinfoEndpointUris("/path/userinfo_endpoint");
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("https://www.fabrikam.com/path/authorization_endpoint",
                (string) response[Metadata.AuthorizationEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/introspection_endpoint",
                (string) response[Metadata.IntrospectionEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/logout_endpoint",
                (string) response[Metadata.EndSessionEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/revocation_endpoint",
                (string) response[Metadata.RevocationEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/token_endpoint",
                (string) response[Metadata.TokenEndpoint]);

            Assert.Equal("https://www.fabrikam.com/path/userinfo_endpoint",
                (string) response[Metadata.UserinfoEndpoint]);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenTokenEndpointIsDisabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Configure(options => options.GrantTypes.Clear());
                options.Configure(options => options.GrantTypes.Add(GrantTypes.Implicit));
                options.SetTokenEndpointUris(Array.Empty<Uri>());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.TokenEndpointAuthMethodsSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenTokenEndpointIsEnabled()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var methods = (string[]) response[Metadata.TokenEndpointAuthMethodsSupported];

            // Assert
            Assert.Contains(ClientAuthenticationMethods.ClientSecretBasic, methods);
            Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenIntrospectionEndpointIsDisabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.SetIntrospectionEndpointUris(Array.Empty<Uri>());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.IntrospectionEndpointAuthMethodsSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenIntrospectionEndpointIsEnabled()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var methods = (string[]) response[Metadata.IntrospectionEndpointAuthMethodsSupported];

            // Assert
            Assert.Contains(ClientAuthenticationMethods.ClientSecretBasic, methods);
            Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenRevocationEndpointIsDisabled()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.SetRevocationEndpointUris(Array.Empty<Uri>());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.RevocationEndpointAuthMethodsSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenRevocationEndpointIsEnabled()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var methods = (string[]) response[Metadata.RevocationEndpointAuthMethodsSupported];

            // Assert
            Assert.Contains(ClientAuthenticationMethods.ClientSecretBasic, methods);
            Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        }

        [Fact]
        public async Task HandleConfigurationRequest_ConfiguredGrantTypesAreReturned()
        {
            // Arrange
            var client = CreateClient(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
            {
                options.GrantTypes.Clear();
                options.GrantTypes.Add(GrantTypes.AuthorizationCode);
                options.GrantTypes.Add(GrantTypes.Password);
            }));

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var types = (string[]) response[Metadata.GrantTypesSupported];

            // Assert
            Assert.Equal(2, types.Length);
            Assert.Contains(GrantTypes.AuthorizationCode, types);
            Assert.Contains(GrantTypes.Password, types);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoSupportedCodeChallengeMethodsPropertyIsReturnedWhenNoMethodIsConfigured()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.PostConfigure<OpenIddictServerOptions>(options => options.CodeChallengeMethods.Clear());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.CodeChallengeMethodsSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_ConfiguredCodeChallengeMethodsAreReturned()
        {
            // Arrange
            var client = CreateClient(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
            {
                options.CodeChallengeMethods.Clear();
                options.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);
                options.CodeChallengeMethods.Add(CodeChallengeMethods.Plain);
            }));

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var methods = (string[]) response[Metadata.CodeChallengeMethodsSupported];

            // Assert
            Assert.Equal(2, methods.Length);
            Assert.Contains(CodeChallengeMethods.Sha256, methods);
            Assert.Contains(CodeChallengeMethods.Plain, methods);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoSupportedResponseModesPropertyIsReturnedWhenNoResponseModeIsConfigured()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.PostConfigure<OpenIddictServerOptions>(options => options.ResponseModes.Clear());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.ResponseModesSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_ConfiguredResponseModesAreReturned()
        {
            // Arrange
            var client = CreateClient(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
            {
                options.ResponseModes.Clear();
                options.ResponseModes.Add(ResponseModes.FormPost);
                options.ResponseModes.Add(ResponseModes.Fragment);
            }));

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var modes = (string[]) response[Metadata.ResponseModesSupported];

            // Assert
            Assert.Equal(2, modes.Length);
            Assert.Contains(ResponseModes.FormPost, modes);
            Assert.Contains(ResponseModes.Fragment, modes);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoSupportedResponseTypesPropertyIsReturnedWhenNoResponseTypeIsConfigured()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.PostConfigure<OpenIddictServerOptions>(options => options.ResponseTypes.Clear());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.ResponseTypesSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_ConfiguredResponseTypesAreReturned()
        {
            // Arrange
            var client = CreateClient(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
            {
                options.ResponseTypes.Clear();
                options.ResponseTypes.Add(ResponseTypes.Code);
                options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken);
            }));

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var types = (string[]) response[Metadata.ResponseTypesSupported];

            // Assert
            Assert.Equal(2, types.Length);
            Assert.Contains(ResponseTypes.Code, types);
            Assert.Contains(ResponseTypes.Code + ' ' + ResponseTypes.IdToken, types);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoSupportedScopesPropertyIsReturnedWhenNoScopeIsConfigured()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.PostConfigure<OpenIddictServerOptions>(options => options.Scopes.Clear());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.ScopesSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_ConfiguredScopesAreReturned()
        {
            // Arrange
            var client = CreateClient(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
            {
                options.Scopes.Clear();
                options.Scopes.Add(Scopes.OpenId);
                options.Scopes.Add("custom_scope");
            }));

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var scopes = (string[]) response[Metadata.ScopesSupported];

            // Assert
            Assert.Equal(2, scopes.Length);
            Assert.Contains(Scopes.OpenId, scopes);
            Assert.Contains("custom_scope", scopes);
        }

        [Fact]
        public async Task HandleConfigurationRequest_NoSupportedClaimsPropertyIsReturnedWhenNoClaimIsConfigured()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Services.PostConfigure<OpenIddictServerOptions>(options => options.Claims.Clear());
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False(response.HasParameter(Metadata.ClaimsSupported));
        }

        [Fact]
        public async Task HandleConfigurationRequest_ConfiguredClaimsAreReturned()
        {
            // Arrange
            var client = CreateClient(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
            {
                options.Claims.Clear();
                options.Claims.Add(Claims.Profile);
                options.Claims.Add("custom_claim");
            }));

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var claims = (string[]) response[Metadata.ClaimsSupported];

            // Assert
            Assert.Equal(2, claims.Length);
            Assert.Contains(Claims.Profile, claims);
            Assert.Contains("custom_claim", claims);
        }

        [Fact]
        public async Task HandleConfigurationRequest_SupportedSubjectTypesAreCorrectlyReturned()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var types = (string[]) response[Metadata.SubjectTypesSupported];

            // Assert
            Assert.Contains(SubjectTypes.Public, types);
        }

        [Theory]
        [InlineData(Algorithms.RsaSha256)]
        [InlineData(Algorithms.RsaSha384)]
        [InlineData(Algorithms.RsaSha512)]
#if SUPPORTS_ECDSA
        [InlineData(Algorithms.EcdsaSha256)]
        [InlineData(Algorithms.EcdsaSha384)]
        [InlineData(Algorithms.EcdsaSha512)]
#endif
        public async Task HandleConfigurationRequest_SigningAlgorithmsAreCorrectlyReturned(string algorithm)
        {
            // Arrange
            var credentials = new SigningCredentials(Mock.Of<AsymmetricSecurityKey>(), algorithm);

            var client = CreateClient(options =>
            {
                options.Configure(options => options.SigningCredentials.Clear());
                options.AddSigningCredentials(credentials);
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var algorithms = (string[]) response[Metadata.IdTokenSigningAlgValuesSupported];

            // Assert
            Assert.Contains(algorithm, algorithms);
        }

        [Fact]
        public async Task HandleConfigurationRequest_SymmetricSigningKeysAreIgnored()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.Configure(options => options.SigningCredentials.Clear());
                options.AddSigningKey(new SymmetricSecurityKey(new byte[256 / 8]));
                options.AddSigningCredentials(new SigningCredentials(Mock.Of<AsymmetricSecurityKey>(), Algorithms.RsaSha256));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var algorithms = (string[]) response[Metadata.IdTokenSigningAlgValuesSupported];

            // Assert
            Assert.Single(algorithms);
            Assert.Contains(Algorithms.RsaSha256, algorithms);
        }

        [Fact]
        public async Task HandleConfigurationRequest_DuplicateSigningAlgorithmsAreIgnored()
        {
            // Arrange
            var credentials = new SigningCredentials(Mock.Of<AsymmetricSecurityKey>(), SecurityAlgorithms.RsaSha256Signature);

            var client = CreateClient(options =>
            {
                options.Configure(options => options.SigningCredentials.Clear());
                options.AddSigningCredentials(credentials);
                options.AddSigningCredentials(credentials);
                options.AddSigningCredentials(credentials);
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");
            var algorithms = (string[]) response[Metadata.IdTokenSigningAlgValuesSupported];

            // Assert
            Assert.Single(algorithms);
        }

        [Fact]
        public async Task HandleConfigurationRequest_SupportedParametersAreReturned()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.False((bool) response[Metadata.ClaimsParameterSupported]);
            Assert.False((bool) response[Metadata.RequestParameterSupported]);
            Assert.False((bool) response[Metadata.RequestUriParameterSupported]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task HandleConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task HandleConfigurationRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task HandleConfigurationRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyConfigurationResponse_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyConfigurationResponseContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyConfigurationResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyConfigurationResponseContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/openid-configuration");

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
        }

        [Theory]
        [InlineData(nameof(HttpMethod.Delete))]
        [InlineData(nameof(HttpMethod.Head))]
        [InlineData(nameof(HttpMethod.Options))]
        [InlineData(nameof(HttpMethod.Post))]
        [InlineData(nameof(HttpMethod.Put))]
        [InlineData(nameof(HttpMethod.Trace))]
        public async Task ExtractCryptographyRequest_UnexpectedMethodReturnsAnError(string method)
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.SendAsync(method, "/.well-known/jwks", new OpenIddictRequest());

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
        public async Task ExtractCryptographyRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractCryptographyRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ExtractCryptographyRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractCryptographyRequestContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ExtractCryptographyRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ExtractCryptographyRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task ValidateCryptographyRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateCryptographyRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task ValidateCryptographyRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateCryptographyRequestContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ValidateCryptographyRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ValidateCryptographyRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Theory]
        [InlineData(SecurityAlgorithms.HmacSha256Signature)]
        [InlineData(SecurityAlgorithms.HmacSha384Signature)]
        [InlineData(SecurityAlgorithms.HmacSha512Signature)]
#if !SUPPORTS_ECDSA
        [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
        [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
#endif
        public async Task HandleCryptographyRequest_UnsupportedSecurityKeysAreIgnored(string algorithm)
        {
            // Arrange
            var factory = Mock.Of<CryptoProviderFactory>(mock => !mock.IsSupportedAlgorithm(algorithm, It.IsAny<SecurityKey>()));
            var key = Mock.Of<SecurityKey>(mock => mock.CryptoProviderFactory == factory);

            var client = CreateClient(options =>
            {
                options.AddSigningCredentials(new SigningCredentials(key, algorithm));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");
            var keys = (JsonElement) response[Parameters.Keys];

            // Assert
            Assert.Equal(1, keys.GetArrayLength());
            Assert.Equal(Algorithms.RsaSha256, keys[0].GetProperty(JsonWebKeyParameterNames.Alg).GetString());
        }

        [Fact]
        public async Task HandleCryptographyRequest_RsaSecurityKeysAreCorrectlyExposed()
        {
            // Arrange
            var parameters = new RSAParameters
            {
                D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
                DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
                DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
                Exponent = Convert.FromBase64String("AQAB"),
                InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
                Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
                P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
                Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
            };

            var client = CreateClient(options =>
            {
                options.Configure(options => options.SigningCredentials.Clear());
                options.AddSigningKey(new RsaSecurityKey(parameters));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");
            var key = response[Parameters.Keys]?[0];

            // Assert
            Assert.Null(key?[JsonWebKeyParameterNames.D]);
            Assert.Null(key?[JsonWebKeyParameterNames.DP]);
            Assert.Null(key?[JsonWebKeyParameterNames.DQ]);
            Assert.Null(key?[JsonWebKeyParameterNames.P]);
            Assert.Null(key?[JsonWebKeyParameterNames.Q]);

            Assert.Equal(parameters.Exponent, Base64UrlEncoder.DecodeBytes((string) key?[JsonWebKeyParameterNames.E]));
            Assert.Equal(parameters.Modulus, Base64UrlEncoder.DecodeBytes((string) key?[JsonWebKeyParameterNames.N]));
        }

#if SUPPORTS_ECDSA
        [Theory]
        [InlineData(
            /* oid: */ "1.2.840.10045.3.1.7",
            /* curve: */ nameof(ECCurve.NamedCurves.nistP256),
            /* d: */ "C0vacBwq1FnQ1N0FHXuuwTlw7Or0neOm2r3AdIKLDKI=",
            /* x: */ "7eu+fVtuma+LVD4eH6CxrBX8366cnhPpvgeoeYL7oqw=",
            /* y: */ "4qRkITJZ4p5alm0VpLPd+I11wq8vMUHUhbJm1Crx+Zs=")]
        [InlineData(
            /* oid: */ "1.3.132.0.34",
            /* curve: */ nameof(ECCurve.NamedCurves.nistP384),
            /* d: */ "B2JSdvTbRD/T5Sv7QsGBHPX9yGo2zn3Et5OWrjNauQ2kl+jFkXg5Iy2Vfak7W0ZQ",
            /* x: */ "qqsUwddWjXhCWiaUCOUORJIzvp6QDXv1vroHPR4N0C3UqSKkJ5hNiBHaYdRYCnvC",
            /* y: */ "QpbQFKBOXgeAKQQub/9QWZPvzNEjXq7aJjHlw4hiY+9QhGPn4qHUaeeI0qlaJ/t2")]
        [InlineData(
            /* oid: */ "1.3.132.0.35",
            /* curve: */ nameof(ECCurve.NamedCurves.nistP521),
            /* d: */ "ALong1stsWvTLufObn3SPfM8s9VsTG73nXv4mkzGFUmB1r7rda+cpYXU99rFV/kX6zBkFl7Y9TZ2ZyZLFnyUpE4j",
            /* x: */ "AS+aCMpMbSO4ga/hUsVIIidqmcQiiT+N9o/5hJ9UVA/vHAKDvWTjuKz+JZfOiR9J+GDUcDZS56UbGG83IosMJMM6",
            /* y: */ "AcYkfsb/kTKpcPhYsRPAYV7ibwTN/CdiAM8QuCElAV6wBGfuX1LUmK6ldDVJjytpSz1EmGvzR0T7UCcZcgITqWc2")]
        public async Task HandleCryptographyRequest_EcdsaSecurityKeysAreCorrectlyExposed(
            string oid, string curve, string d, string x, string y)
        {
            // Arrange
            var parameters = new ECParameters
            {
                Curve = ECCurve.CreateFromOid(new Oid(oid, curve)),
                D = Convert.FromBase64String(d),
                Q = new ECPoint
                {
                    X = Convert.FromBase64String(x),
                    Y = Convert.FromBase64String(y)
                }
            };

            var algorithm = ECDsa.Create(parameters);

            var client = CreateClient(options =>
            {
                options.Configure(options => options.SigningCredentials.Clear());
                options.AddSigningKey(new ECDsaSecurityKey(algorithm));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");
            var key = response[Parameters.Keys]?[0];

            // Assert
            Assert.Null(key?[JsonWebKeyParameterNames.D]);

            Assert.Equal(parameters.Q.X, Base64UrlEncoder.DecodeBytes((string) key?[JsonWebKeyParameterNames.X]));
            Assert.Equal(parameters.Q.Y, Base64UrlEncoder.DecodeBytes((string) key?[JsonWebKeyParameterNames.Y]));
        }
#endif

        [Fact]
        public async Task HandleCryptographyRequest_X509CertificatesAreCorrectlyExposed()
        {
            // Arrange
            var client = CreateClient();

            // Act
            var response = await client.GetAsync("/.well-known/jwks");
            var key = response[Parameters.Keys]?[0];

            // Assert
            Assert.Equal("BSxeQhXNDB4VBeCOavOtvvv9eCI", (string) key?[JsonWebKeyParameterNames.X5t]);
            Assert.Equal("MIIDPjCCAiqgAwIBAgIQlLEp+P+WKYtEAemhSKSUTTAJBgUrDgMCHQUAMC0xKzApBgNVBAMTIk93aW4uU2VjdXJpdHkuT3BlbklkQ29ubmVjdC5TZXJ2ZXIwHhcNOTkxMjMxMjIwMDAwWhcNNDkxMjMxMjIwMDAwWjAtMSswKQYDVQQDEyJPd2luLlNlY3VyaXR5Lk9wZW5JZENvbm5lY3QuU2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwD/4uMNSIu+JlPRrtFR8Tm2LAwSOmglvJai6edFrdvDvk6xWzxYkMoIt4v13lFiIAUfI1vyZ1M0hWQfrifyweuzZu06DyWTUZkp9ervhTxK27HFN7XTuaRxHaXLR4KnhA+Nk8bBXN895OZh9g9Hf5+zsHpe17zgikwcyZtF+9OEG16oz7lKRgXGCIeeVZuSZ5Qf4yePwKMZqsx+lTOiZJ3JMs+gytvIpdZ1NWzcMX0XTcVTgvnBeU0O3NR6DQ41+SrGsojk11bd6kP6mVmDkA0K9kc2eh7q1wyJOeTNuCKRqLthwJ5m46/KRsxgY7ND6qHc1L60SqsFlYCJNEy7EdwIDAQABo2IwYDBeBgNVHQEEVzBVgBDQX+HKPiztLNvT3jQeBXqToS8wLTErMCkGA1UEAxMiT3dpbi5TZWN1cml0eS5PcGVuSWRDb25uZWN0LlNlcnZlcoIQlLEp+P+WKYtEAemhSKSUTTAJBgUrDgMCHQUAA4IBAQCxbCF5thB+ypGpudLAjv+l3M2VhNITJeR9j7jMlCSMVHvW7iMOL5W++zKvHMMAWuITLgPXTZ4ktsjeVQxWdnS2IcU7SwB9SeLbOMk4lLizoUevkiNaf6v+Hskm5LiH6+k8Zsl0INHyIjF9XlALTh91EqQ820cotDXaQIhHabQy892+dBmGWhSE1kP56IvOPzlLdSTkrcfcOu9gzwPVfuTDWH8Hrmo3FXz/fADmE7ea+yE1ZBeKhaN8kaFTs5zrprJ1BnmegnrjDY3RFgqcTTetahv0VBS0/jHSTIsAXflEPGW7LbHimzcgMytFU4fFtPVbek5eunakhu/JdENbbVmT", (string) key?[JsonWebKeyParameterNames.X5c]?[0]);
        }

        [Theory]
        [InlineData("custom_error", null, null)]
        [InlineData("custom_error", "custom_description", null)]
        [InlineData("custom_error", "custom_description", "custom_uri")]
        [InlineData(null, "custom_description", null)]
        [InlineData(null, "custom_description", "custom_uri")]
        [InlineData(null, null, "custom_uri")]
        [InlineData(null, null, null)]
        public async Task HandleCryptographyRequest_AllowsRejectingRequest(string error, string description, string uri)
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleCryptographyRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.Reject(error, description, uri);

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
            Assert.Equal(description, response.ErrorDescription);
            Assert.Equal(uri, response.ErrorUri);
        }

        [Fact]
        public async Task HandleCryptographyRequest_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleCryptographyRequestContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task HandleCryptographyRequest_AllowsSkippingHandler()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<HandleCryptographyRequestContext>(builder =>
                    builder.UseInlineHandler(context =>
                    {
                        context.SkipRequest();

                        return default;
                    }));
            });

            // Act
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("Bob le Magnifique", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyCryptographyResponse_AllowsHandlingResponse()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyCryptographyResponseContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("Bob le Bricoleur", (string) response["name"]);
        }

        [Fact]
        public async Task ApplyCryptographyResponse_ResponseContainsCustomParameters()
        {
            // Arrange
            var client = CreateClient(options =>
            {
                options.EnableDegradedMode();

                options.AddEventHandler<ApplyCryptographyResponseContext>(builder =>
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
            var response = await client.GetAsync("/.well-known/jwks");

            // Assert
            Assert.Equal("custom_value", (string) response["custom_parameter"]);
            Assert.Equal(new[] { "custom_value_1", "custom_value_2" }, (string[]) response["parameter_with_multiple_values"]);
        }
    }
}
