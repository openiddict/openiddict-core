using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Cookies;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Mvc.Client {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            services.Configure<SharedAuthenticationOptions>(options => {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            services.AddAuthentication();
            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            app.UseIISPlatformHandler(options => {
                options.FlowWindowsAuthentication = false;
            });

            app.UseStaticFiles();

            // Insert a new cookies middleware in the pipeline to store the user
            // identity after he has been redirected from the identity provider.
            app.UseCookieAuthentication(options => {
                options.AutomaticAuthenticate = true;
                options.AutomaticChallenge = true;
                options.LoginPath = new PathString("/signin");
            });

            app.UseOpenIdConnectAuthentication(options => {
                // Note: these settings must match the application details
                // inserted in the database at the server level.
                options.ClientId = "myClient";
                options.ClientSecret = "secret_secret_secret";
                options.PostLogoutRedirectUri = "http://localhost:53507/";

                options.RequireHttpsMetadata = false;
                options.GetClaimsFromUserInfoEndpoint = true;

                // Use the authorization code flow.
                options.ResponseType = OpenIdConnectResponseTypes.Code;

                // Note: setting the Authority allows the OIDC client middleware to automatically
                // retrieve the identity provider's configuration and spare you from setting
                // the different endpoints URIs or the token validation parameters explicitly.
                options.Authority = "http://localhost:54540/";

                // Note: the resource property represents the different endpoints the
                // access token should be issued for (values must be space-delimited).
                options.Resource = "http://localhost:54540/";

                options.Scope.Add("email");
            });


            app.UseMvc();
        }
    }
}