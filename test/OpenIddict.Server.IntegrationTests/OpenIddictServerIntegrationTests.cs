/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Text;
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

                    options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                    {
                        builder.UseInlineHandler(context =>
                        {
                            var identity = new ClaimsIdentity("Bearer");
                            identity.AddClaim(Claims.Subject, "Bob le Magnifique");

                            context.Principal = new ClaimsPrincipal(identity);
                            context.HandleAuthentication();

                            return default;
                        });

                        builder.SetOrder(int.MaxValue);
                    });

                    options.AddEventHandler<HandleTokenRequestContext>(builder =>
                    {
                        builder.UseInlineHandler(context =>
                        {
                            var identity = new ClaimsIdentity("Bearer");
                            identity.AddClaim(Claims.Subject, "Bob le Magnifique");

                            context.Principal = new ClaimsPrincipal(identity);
                            context.HandleAuthentication();

                            return default;
                        });

                        builder.SetOrder(int.MaxValue);
                    });
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
