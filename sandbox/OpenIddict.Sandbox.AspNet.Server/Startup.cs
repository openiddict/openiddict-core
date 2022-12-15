using System;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Autofac.Integration.Mvc;
using Autofac.Integration.WebApi;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using OpenIddict.Abstractions;
using OpenIddict.Client.Owin;
using OpenIddict.Sandbox.AspNet.Server.Models;
using OpenIddict.Server.Owin;
using OpenIddict.Validation.Owin;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;

[assembly: OwinStartup(typeof(OpenIddict.Sandbox.AspNet.Server.Startup))]
namespace OpenIddict.Sandbox.AspNet.Server
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);

            var container = CreateContainer();

            // Register the Autofac scope injector middleware.
            app.UseAutofacLifetimeScopeInjector(container);

            // Register the OpenIddict middleware.
            app.UseMiddlewareFromContainer<OpenIddictClientOwinMiddleware>();
            app.UseMiddlewareFromContainer<OpenIddictServerOwinMiddleware>();
            app.UseMiddlewareFromContainer<OpenIddictValidationOwinMiddleware>();

            // Configure ASP.NET MVC 5.2 to use Autofac when activating controller instances.
            DependencyResolver.SetResolver(new AutofacDependencyResolver(container));

            // Configure ASP.NET MVC 5.2 to use Autofac when activating controller instances
            // and infer the Web API routes using the HTTP attributes used in the controllers.
            var configuration = new HttpConfiguration
            {
                DependencyResolver = new AutofacWebApiDependencyResolver(container)
            };

            configuration.MapHttpAttributeRoutes();

            // Register the Autofac Web API integration and Web API middleware.
            app.UseAutofacWebApi(configuration);
            app.UseWebApi(configuration);

            // Seed the database with the sample client using the OpenIddict application manager.
            // Note: in a real world application, this step should be part of a setup script.
            Task.Run(async delegate
            {
                using var scope = container.BeginLifetimeScope();

                var context = scope.Resolve<ApplicationDbContext>();
                context.Database.CreateIfNotExists();

                var manager = scope.Resolve<IOpenIddictApplicationManager>();

                if (await manager.FindByClientIdAsync("mvc") is null)
                {
                    await manager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "mvc",
                        ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                        ConsentType = ConsentTypes.Explicit,
                        DisplayName = "MVC client application",
                        RedirectUris =
                        {
                            new Uri("https://localhost:44378/callback/login/local")
                        },
                        PostLogoutRedirectUris =
                        {
                            new Uri("https://localhost:44378/callback/logout/local")
                        },
                        Permissions =
                        {
                            Permissions.Endpoints.Authorization,
                            Permissions.Endpoints.Logout,
                            Permissions.Endpoints.Token,
                            Permissions.GrantTypes.AuthorizationCode,
                            Permissions.GrantTypes.RefreshToken,
                            Permissions.ResponseTypes.Code,
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Roles,
                            Permissions.Prefixes.Scope + "demo_api"
                        },
                        Requirements =
                        {
                            Requirements.Features.ProofKeyForCodeExchange
                        }
                    });
                }

                if (await manager.FindByClientIdAsync("postman") is null)
                {
                    await manager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "postman",
                        ConsentType = ConsentTypes.Systematic,
                        DisplayName = "Postman",
                        RedirectUris =
                        {
                            new Uri("https://oauth.pstmn.io/v1/callback")
                        },
                        Permissions =
                        {
                            Permissions.Endpoints.Authorization,
                            Permissions.Endpoints.Device,
                            Permissions.Endpoints.Token,
                            Permissions.GrantTypes.AuthorizationCode,
                            Permissions.GrantTypes.DeviceCode,
                            Permissions.GrantTypes.Password,
                            Permissions.GrantTypes.RefreshToken,
                            Permissions.ResponseTypes.Code,
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Roles
                        }
                    });
                }
            }).GetAwaiter().GetResult();
        }

        private static IContainer CreateContainer()
        {
            var services = new ServiceCollection();

            services.AddOpenIddict()

                // Register the OpenIddict core components.
                .AddCore(options =>
                {
                    // Configure OpenIddict to use the Entity Framework 6.x stores and models.
                    // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                    options.UseEntityFramework()
                           .UseDbContext<ApplicationDbContext>();

                    // Developers who prefer using MongoDB can remove the previous lines
                    // and configure OpenIddict to use the specified MongoDB database:
                    // options.UseMongoDb()
                    //        .UseDatabase(new MongoClient().GetDatabase("openiddict"));
                })

                // Register the OpenIddict client components.
                .AddClient(options =>
                {
                    // Enable the redirection endpoint needed to handle the callback stage.
                    //
                    // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                    // URI per provider, unless all the registered providers support returning a special "iss"
                    // parameter containing their URL as part of authorization responses. For more information,
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                    options.SetRedirectionEndpointUris("callback/login/github");

                    // Note: this sample uses the code flow, but you can enable the other flows if necessary.
                    options.AllowAuthorizationCodeFlow();

                    // Register the signing and encryption credentials used to protect
                    // sensitive data like the state tokens produced by OpenIddict.
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    // Register the OWIN host and configure the OWIN-specific options.
                    options.UseOwin()
                           .EnableRedirectionEndpointPassthrough();

                    // Register the System.Net.Http integration and use the identity of the current
                    // assembly as a more specific user agent, which can be useful when dealing with
                    // providers that use the user agent as a way to throttle requests (e.g Reddit).
                    options.UseSystemNetHttp()
                           .SetProductInformation(typeof(Startup).Assembly);

                    // Register the Web providers integrations.
                    options.UseWebProviders()
                           .UseGitHub(options =>
                           {
                               options.SetClientId("c4ade52327b01ddacff3")
                                      .SetClientSecret("da6bed851b75e317bf6b2cb67013679d9467c122")
                                      .SetRedirectUri("callback/login/github");
                           });
                })

                // Register the OpenIddict server components.
                .AddServer(options =>
                {
                    // Enable the authorization, device, introspection,
                    // logout, token, userinfo and verification endpoints.
                    options.SetAuthorizationEndpointUris("connect/authorize")
                           .SetDeviceEndpointUris("connect/device")
                           .SetIntrospectionEndpointUris("connect/introspect")
                           .SetLogoutEndpointUris("connect/logout")
                           .SetTokenEndpointUris("connect/token")
                           .SetUserinfoEndpointUris("connect/userinfo")
                           .SetVerificationEndpointUris("connect/verify");

                    // Note: this sample uses the code, device code, password and refresh token flows, but you
                    // can enable the other flows if you need to support implicit or client credentials.
                    options.AllowAuthorizationCodeFlow()
                           .AllowDeviceCodeFlow()
                           .AllowPasswordFlow()
                           .AllowRefreshTokenFlow();

                    // Mark the "email", "profile", "roles" and "demo_api" scopes as supported scopes.
                    options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "demo_api");

                    // Register the signing and encryption credentials.
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    // Force client applications to use Proof Key for Code Exchange (PKCE).
                    options.RequireProofKeyForCodeExchange();

                    // Register the OWIN host and configure the OWIN-specific options.
                    options.UseOwin()
                           .EnableAuthorizationEndpointPassthrough()
                           .EnableLogoutEndpointPassthrough()
                           .EnableTokenEndpointPassthrough();
                })

                // Register the OpenIddict validation components.
                .AddValidation(options =>
                {
                    // Import the configuration from the local OpenIddict server instance.
                    options.UseLocalServer();

                    // Register the OWIN host.
                    options.UseOwin();
                });

            // Create a new Autofac container and import the OpenIddict services.
            var builder = new ContainerBuilder();
            builder.Populate(services);

            // Register the MVC controllers.
            builder.RegisterControllers(typeof(Startup).Assembly);

            // Register the Web API controllers.
            builder.RegisterApiControllers(typeof(Startup).Assembly);

            return builder.Build();
        }
    }
}
