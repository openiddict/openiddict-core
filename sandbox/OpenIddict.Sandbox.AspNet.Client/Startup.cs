using System;
using System.Web.Mvc;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Autofac.Integration.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Client;
using OpenIddict.Client.Owin;
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
        }

        private static IContainer CreateContainer()
        {
            var services = new ServiceCollection();

            services.AddOpenIddict()
                .AddClient(options =>
                {
                    // Add a client registration matching the client application definition in the server project.
                    options.AddRegistration(new OpenIddictClientRegistration
                    {
                        Issuer = new Uri("https://localhost:44349/", UriKind.Absolute),

                        ClientId = "mvc",
                        ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                        RedirectUri = new Uri("https://localhost:44378/signin-oidc", UriKind.Absolute),
                        Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
                    });

                    // Enable the redirection endpoint needed to handle the callback stage.
                    options.SetRedirectionEndpointUris("/signin-oidc");

                    // Register the OWIN host and configure the OWIN-specific options.
                    options.UseOwin()
                           .EnableRedirectionEndpointPassthrough();

                    // Register the signing and encryption credentials used to protect
                    // sensitive data like the state tokens produced by OpenIddict.
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    // Register the System.Net.Http integration.
                    options.UseSystemNetHttp();
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
