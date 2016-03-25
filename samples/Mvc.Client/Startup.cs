using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Mvc.Client {
    public class Startup {
        public static void Main(string[] args) {
            var application = new WebHostBuilder()
                .UseDefaultHostingConfiguration(args)
                .UseIISPlatformHandlerUrl()
                .UseServer("Microsoft.AspNetCore.Server.Kestrel")
                .UseStartup<Startup>()
                .Build();

            application.Run();
        }

        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication(options => {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            services.AddMvc();
            services.AddMvcDnx();
        }

        public void Configure(IApplicationBuilder app, ILoggerFactory factory) {
            factory.AddConsole();
            factory.AddDebug();

            app.UseIISPlatformHandler();

            app.UseForwardedHeaders(new ForwardedHeadersOptions {
                ForwardedHeaders = ForwardedHeaders.All
            });

            app.UseDeveloperExceptionPage();

            app.UseStaticFiles();

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                LoginPath = new PathString("/signin")
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectOptions {
                // Note: these settings must match the application details
                // inserted in the database at the server level.
                ClientId = "myClient",
                ClientSecret = "secret_secret_secret",
                PostLogoutRedirectUri = "http://localhost:53507/",

                RequireHttpsMetadata = false,
                GetClaimsFromUserInfoEndpoint = true,
                SaveTokens = true,

                // Use the authorization code flow.
                ResponseType = OpenIdConnectResponseTypes.Code,

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                Authority = "http://localhost:54540/",

                Scope = { "email", "roles" }
            });

            app.UseMvc();
        }
    }
}