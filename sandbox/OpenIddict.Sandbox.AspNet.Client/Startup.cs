using System;
using System.Web.Mvc;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Autofac.Integration.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Client;
using OpenIddict.Client.Owin;
using OpenIddict.Sandbox.AspNetCore.Server.Models;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNet.Client
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var container = CreateContainer();

            // Register the Autofac scope injector middleware.
            app.UseAutofacLifetimeScopeInjector(container);

            // Register the cookie middleware responsible of storing the user sessions.
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                ExpireTimeSpan = TimeSpan.FromMinutes(50),
                SlidingExpiration = false
            });

            // Register the OpenIddict client middleware.
            app.UseMiddlewareFromContainer<OpenIddictClientOwinMiddleware>();

            // Configure ASP.NET MVC 5.2 to use Autofac when activating controller instances.
            DependencyResolver.SetResolver(new AutofacDependencyResolver(container));

            // Create the database used by the OpenIddict client stack to store tokens.
            // Note: in a real world application, this step should be part of a setup script.
            using var scope = container.BeginLifetimeScope();

            var context = scope.Resolve<ApplicationDbContext>();
            context.Database.CreateIfNotExists();
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
                    options.SetRedirectionEndpointUris("/signin-oidc");

                    // Register the signing and encryption credentials used to protect
                    // sensitive data like the state tokens produced by OpenIddict.
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    // Register the OWIN host and configure the OWIN-specific options.
                    options.UseOwin()
                           .EnableRedirectionEndpointPassthrough();

                    // Register the System.Net.Http integration.
                    options.UseSystemNetHttp();

                    // Add a client registration matching the client application definition in the server project.
                    options.AddRegistration(new OpenIddictClientRegistration
                    {
                        Issuer = new Uri("https://localhost:44349/", UriKind.Absolute),

                        ClientId = "mvc",
                        ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                        RedirectUri = new Uri("https://localhost:44378/signin-oidc", UriKind.Absolute),
                        Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
                    });
                });

            // Create a new Autofac container and import the OpenIddict services.
            var builder = new ContainerBuilder();
            builder.Populate(services);

            // Register the MVC controllers.
            builder.RegisterControllers(typeof(Startup).Assembly);

            return builder.Build();
        }
    }
}
