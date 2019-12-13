/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server.FunctionalTests
{
    public abstract partial class OpenIddictServerIntegrationTests
    {
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
