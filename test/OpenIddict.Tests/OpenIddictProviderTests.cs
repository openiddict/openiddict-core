using System;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Moq;
using Newtonsoft.Json;
using OpenIddict.Core;
using OpenIddict.Models;

namespace OpenIddict.Tests
{
    public partial class OpenIddictProviderTests
    {
        public const string AuthorizationEndpoint = "/connect/authorize";
        public const string ConfigurationEndpoint = "/.well-known/openid-configuration";
        public const string IntrospectionEndpoint = "/connect/introspect";
        public const string LogoutEndpoint = "/connect/logout";
        public const string RevocationEndpoint = "/connect/revoke";
        public const string TokenEndpoint = "/connect/token";
        public const string UserinfoEndpoint = "/connect/userinfo";

        private static TestServer CreateAuthorizationServer(Action<OpenIddictBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddOptions();
                services.AddDistributedMemoryCache();

                // Note: the following client_id/client_secret are fake and are only
                // used to test the metadata returned by the discovery endpoint.
                services.AddAuthentication()
                    .AddFacebook(options =>
                    {
                        options.ClientId = "16018790-E88E-4553-8036-BB342579FF19";
                        options.ClientSecret = "3D6499AF-5607-489B-815A-F3ACF1617296";
                        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    })

                    .AddGoogle(options =>
                    {
                        options.ClientId = "BAF437A5-87FA-4D06-8EFD-F9BA96CCEDC4";
                        options.ClientSecret = "27DF07D3-6B03-4EE0-95CD-3AC16782216B";
                        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    });

                // Replace the default OpenIddict managers.
                services.AddSingleton(CreateApplicationManager());
                services.AddSingleton(CreateAuthorizationManager());
                services.AddSingleton(CreateTokenManager());

                services.AddOpenIddict(options =>
                {
                    // Disable the transport security requirement during testing.
                    options.DisableHttpsRequirement();

                    // Enable the tested endpoints.
                    options.EnableAuthorizationEndpoint(AuthorizationEndpoint)
                           .EnableIntrospectionEndpoint(IntrospectionEndpoint)
                           .EnableLogoutEndpoint(LogoutEndpoint)
                           .EnableRevocationEndpoint(RevocationEndpoint)
                           .EnableTokenEndpoint(TokenEndpoint)
                           .EnableUserinfoEndpoint(UserinfoEndpoint);

                    // Enable the tested flows.
                    options.AllowAuthorizationCodeFlow()
                           .AllowClientCredentialsFlow()
                           .AllowImplicitFlow()
                           .AllowPasswordFlow()
                           .AllowRefreshTokenFlow();

                    // Register the X.509 certificate used to sign the identity tokens.
                    options.AddSigningCertificate(
                        assembly: typeof(OpenIddictProviderTests).GetTypeInfo().Assembly,
                        resource: "OpenIddict.Tests.Certificate.pfx",
                        password: "OpenIddict");

                    // Note: overriding the default data protection provider is not necessary for the tests to pass,
                    // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                    // helps make the unit tests run faster, as no registry or disk access is required in this case.
                    options.UseDataProtectionProvider(new EphemeralDataProtectionProvider(new LoggerFactory()));

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });
            });

            builder.Configure(app =>
            {
                app.UseStatusCodePages(context =>
                {
                    context.HttpContext.Response.Headers[HeaderNames.ContentType] = "application/json";

                    return context.HttpContext.Response.WriteAsync(JsonConvert.SerializeObject(new
                    {
                        error_custom = OpenIdConnectConstants.Errors.InvalidRequest
                    }));
                });

                app.Use(next => context =>
                {
                    if (context.Request.Path != "/authorize-status-code-middleware" &&
                        context.Request.Path != "/logout-status-code-middleware")
                    {
                        var feature = context.Features.Get<IStatusCodePagesFeature>();
                        feature.Enabled = false;
                    }

                    return next(context);
                });

                app.UseAuthentication();

                app.Run(context =>
                {
                    var request = context.GetOpenIdConnectRequest();
                    if (request.IsAuthorizationRequest() || request.IsTokenRequest())
                    {
                        var identity = new ClaimsIdentity(OpenIdConnectServerDefaults.AuthenticationScheme);
                        identity.AddClaim(OpenIdConnectConstants.Claims.Subject, "Bob le Magnifique");

                        var ticket = new AuthenticationTicket(
                            new ClaimsPrincipal(identity),
                            new AuthenticationProperties(),
                            OpenIdConnectServerDefaults.AuthenticationScheme);

                        ticket.SetScopes(request.GetScopes());

                        if (request.HasParameter("attach-authorization"))
                        {
                            ticket.SetProperty(OpenIddictConstants.Properties.AuthorizationId, "1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70");
                        }

                        return context.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);
                    }

                    else if (request.IsLogoutRequest())
                    {
                        return context.SignOutAsync(OpenIdConnectServerDefaults.AuthenticationScheme);
                    }

                    else if (request.IsUserinfoRequest())
                    {
                        context.Response.Headers[HeaderNames.ContentType] = "application/json";

                        return context.Response.WriteAsync(JsonConvert.SerializeObject(new
                        {
                            access_token = request.AccessToken,
                            sub = "Bob le Bricoleur"
                        }));
                    }

                    return Task.FromResult(0);
                });
            });

            return new TestServer(builder);
        }

        private static OpenIddictApplicationManager<OpenIddictApplication> CreateApplicationManager(Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>> setup = null)
        {
            var manager = new Mock<OpenIddictApplicationManager<OpenIddictApplication>>(
                Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>(),
                Mock.Of<ILogger<OpenIddictApplicationManager<OpenIddictApplication>>>());

            setup?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(Action<Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>> setup = null)
        {
            var manager = new Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(
                Mock.Of<IOpenIddictAuthorizationStore<OpenIddictAuthorization>>(),
                Mock.Of<ILogger<OpenIddictAuthorizationManager<OpenIddictAuthorization>>>());

            setup?.Invoke(manager);

            return manager.Object;
        }

        private static OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(Action<Mock<OpenIddictTokenManager<OpenIddictToken>>> setup = null)
        {
            var manager = new Mock<OpenIddictTokenManager<OpenIddictToken>>(
                Mock.Of<IOpenIddictTokenStore<OpenIddictToken>>(),
                Mock.Of<ILogger<OpenIddictTokenManager<OpenIddictToken>>>());

            setup?.Invoke(manager);

            return manager.Object;
        }
    }
}
