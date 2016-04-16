using System.Linq;
using AspNet.Security.OAuth.GitHub;
using CryptoHelper;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Mvc.Server.Models;
using Mvc.Server.Services;
using NWebsec.Middleware;
using OpenIddict;
using OpenIddict.Models;

namespace Mvc.Server {
    public class Startup {
        public void ConfigureServices(IServiceCollection services) {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("config.json")
                .AddEnvironmentVariables()
                .Build();

            services.AddMvc();

            services.AddEntityFramework()
                .AddEntityFrameworkSqlServer()
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
            app.UseForwardedHeaders(new ForwardedHeadersOptions {
                ForwardedHeaders = ForwardedHeaders.All
            });

            app.UseDeveloperExceptionPage();

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

            app.UseGoogleAuthentication(new GoogleOptions {
                ClientId = "560027070069-37ldt4kfuohhu3m495hk2j4pjp92d382.apps.googleusercontent.com",
                ClientSecret = "n2Q-GEw9RQjzcRbU3qhfTj8f"
            });

            app.UseTwitterAuthentication(new TwitterOptions {
                ConsumerKey = "6XaCTaLbMqfj6ww3zvZ5g",
                ConsumerSecret = "Il2eFzGIrYhz6BWjYhVXBPQSfZuS4xoHpSSyD9PI"
            });

            app.UseGitHubAuthentication(new GitHubAuthenticationOptions {
                ClientId = "49e302895d8b09ea5656",
                ClientSecret = "98f1bf028608901e9df91d64ee61536fe562064b",
                Scope = { "user:email" }
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

                    var hasher = new PasswordHasher<Application>();

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