using System.Linq;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Data.Entity;
using Microsoft.Dnx.Runtime;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Mvc.Server.Models;
using Mvc.Server.Services;
using OpenIddict.Models;

namespace Mvc.Server {
    public class Startup {
        public Startup(IApplicationEnvironment environment) {
            Configuration = new ConfigurationBuilder()
                .SetBasePath(environment.ApplicationBasePath)
                .AddJsonFile("config.json")
                .AddEnvironmentVariables()
                .Build();
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services) {
            services.AddMvc();

            services.AddEntityFramework()
                .AddSqlServer()
                .AddDbContext<ApplicationDbContext>(options =>
                    options.UseSqlServer(Configuration["Data:DefaultConnection:ConnectionString"]));

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

            app.UseStaticFiles();

            // Add a middleware used to validate access
            // tokens and protect the API endpoints.
            app.UseJwtBearerAuthentication(options => {
                options.Audience = "http://localhost:54540/";
                options.Authority = "http://localhost:54540/";

                // Note: by default, IdentityModel beta8 now refuses to initiate non-HTTPS calls.
                // To work around this limitation, the configuration manager is manually
                // instantiated with a document retriever allowing HTTP calls.
                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    metadataAddress: options.Authority + ".well-known/openid-configuration",
                    configRetriever: new OpenIdConnectConfigurationRetriever(),
                    docRetriever: new HttpDocumentRetriever { RequireHttps = false });
            });

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
            app.UseOpenIddict();

            app.UseMvcWithDefaultRoute();

            using (var context = app.ApplicationServices.GetRequiredService<ApplicationDbContext>()) {
                context.Database.EnsureCreated();

                // Add Mvc.Client to the known applications.
                if (!context.Applications.Any()) {
                    context.Applications.Add(new Application {
                        ApplicationID = "myClient",
                        DisplayName = "My client application",
                        RedirectUri = "http://localhost:53507/oidc",
                        LogoutRedirectUri = "http://localhost:53507/",
                        Secret = "secret_secret_secret",
                        Type = ApplicationType.Confidential
                    });

                    context.SaveChanges();
                }
            }
        }
    }
}