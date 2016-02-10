using System.Linq;
using CryptoHelper;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.HttpOverrides;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Mvc.Server.Models;
using Mvc.Server.Services;
using NWebsec.Middleware;
using OpenIddict;
using OpenIddict.Models;

namespace Mvc.Server {
    public class Startup {
        public static void Main(string[] args) {
            var application = new WebApplicationBuilder()
                .UseConfiguration(WebApplicationConfiguration.GetDefault(args))
                .UseStartup<Startup>()
                .Build();

            application.Run();
        }

        public void ConfigureServices(IServiceCollection services) {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("config.json")
                .AddEnvironmentVariables()
                .Build();

            services.AddMvc();

            services.AddEntityFramework()
                .AddSqlServer()
                .AddDbContext<ApplicationDbContext>(options =>
                    options.UseSqlServer(configuration["Data:DefaultConnection:ConnectionString"]));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders()
                .AddOpenIddict();

            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
        }

        public void Configure(IApplicationBuilder app) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();
            factory.AddDebug();

            app.UseIISPlatformHandler(options => {
                options.FlowWindowsAuthentication = false;
            });

            app.UseOverrideHeaders(options => {
                options.ForwardedOptions = ForwardedHeaders.All;
            });

            app.UseStaticFiles();

            // Add a middleware used to validate access
            // tokens and protect the API endpoints.
            app.UseOAuthValidation();

            // Alternatively, you can also use the introspection middleware.
            // Using it is recommended if your resource server is in a
            // different application/separated from the authorization server.
            // 
            // app.UseOAuthIntrospection(options => {
            //     options.AutomaticAuthenticate = true;
            //     options.AutomaticChallenge = true;
            //     options.Authority = "http://localhost:54540/";
            //     options.Audience = "resource_server";
            //     options.ClientId = "resource_server";
            //     options.ClientSecret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd";
            // });

            app.UseIdentity();

            app.UseGoogleAuthentication(options => {
                options.ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com";
                options.ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f";
            });

            app.UseTwitterAuthentication(options => {
                options.ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g";
                options.ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI";
            });

            // Note: OpenIddict must be added after
            // ASP.NET Identity and the external providers.
            app.UseOpenIddict(options => {
                // You can customize the default Content Security Policy (CSP) by calling UseNWebsec explicitly.
                // This can be useful to allow your HTML views to reference remote scripts/images/styles.
                options.UseNWebsec(directives => {
                    directives.DefaultSources(directive => directive.Self())
                        .ImageSources(directive => directive.Self().CustomSources("*"))
                        .ScriptSources(directive => directive
                            .Self()
                            .UnsafeInline()
                            .CustomSources("https://my.custom.url"))
                        .StyleSources(directive => directive.Self().UnsafeInline());
                });
            });

            app.UseMvcWithDefaultRoute();

            using (var context = app.ApplicationServices.GetRequiredService<ApplicationDbContext>()) {
                context.Database.EnsureCreated();

                // Add Mvc.Client to the known applications.
                if (!context.Applications.Any()) {
                    // Note: when using the introspection middleware, your resource server
                    // MUST be registered as an OAuth2 client and have valid credentials.
                    // 
                    // context.Applications.Add(new Application {
                    //     Id = "resource_server",
                    //     DisplayName = "Main resource server",
                    //     Secret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd"
                    // });

                    context.Applications.Add(new Application {
                        Id = "myClient",
                        DisplayName = "My client application",
                        RedirectUri = "http://localhost:53507/signin-oidc",
                        LogoutRedirectUri = "http://localhost:53507/",
                        Secret = Crypto.HashPassword("secret_secret_secret"),
                        Type = OpenIddictConstants.ApplicationTypes.Confidential
                    });

                    // To test this sample with Postman, use the following settings:
                    // 
                    // * Authorization URL: http://localhost:54540/connect/authorize
                    // * Access token URL: http://localhost:54540/connect/token
                    // * Client ID: postman
                    // * Client secret: [blank] (not used with public clients)
                    // * Scope: openid email profile roles
                    // * Grant type: authorization code
                    // * Request access token locally: yes
                    context.Applications.Add(new Application {
                        Id = "postman",
                        DisplayName = "Postman",
                        RedirectUri = "https://www.getpostman.com/oauth2/callback",
                        Type = OpenIddictConstants.ApplicationTypes.Public
                    });

                    context.SaveChanges();
                }
            }
        }
    }
}