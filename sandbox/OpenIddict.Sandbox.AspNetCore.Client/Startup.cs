using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Client;
using OpenIddict.Sandbox.AspNetCore.Client.Models;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.Client;

public class Startup
{
    public Startup(IConfiguration configuration)
        => Configuration = configuration;

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use Microsoft SQL Server.
            options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"));

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        })

        .AddCookie(options =>
        {
            options.LoginPath = "/login";
            options.LogoutPath = "/logout";
            options.ExpireTimeSpan = TimeSpan.FromMinutes(50);
            options.SlidingExpiration = false;
        });

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations from the database) at regular intervals.
        services.AddQuartz(options =>
        {
            options.UseMicrosoftDependencyInjectionJobFactory();
            options.UseSimpleTypeLoader();
            options.UseInMemoryStore();
        });

        // Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
        services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();

                // Developers who prefer using MongoDB can remove the previous lines
                // and configure OpenIddict to use the specified MongoDB database:
                // options.UseMongoDb()
                //        .UseDatabase(new MongoClient().GetDatabase("openiddict"));

                // Enable Quartz.NET integration.
                options.UseQuartz();
            })

            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Enable the redirection endpoint needed to handle the callback stage.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // address per provider, unless all the registered providers support returning an "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.SetRedirectionEndpointUris(
                    "/callback/login/local",
                    "/callback/login/github",
                    "/callback/login/google",
                    "/callback/login/reddit",
                    "/callback/login/twitter");

                // Enable the post-logout redirection endpoints needed to handle the callback stage.
                options.SetPostLogoutRedirectionEndpointUris(
                    "/callback/logout/local");

                // Note: this sample uses the code flow, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableRedirectionEndpointPassthrough()
                       .EnablePostLogoutRedirectionEndpointPassthrough();

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(Startup).Assembly);

                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    ProviderName = "Local",
                    Issuer = new Uri("https://localhost:44395/", UriKind.Absolute),

                    ClientId = "mvc",
                    ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                    Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" },

                    RedirectUri = new Uri("https://localhost:44381/callback/login/local", UriKind.Absolute),
                    PostLogoutRedirectUri = new Uri("https://localhost:44381/callback/logout/local", UriKind.Absolute)
                });

                // Register the Web providers integrations.
                options.UseWebProviders()
                       .UseGitHub(options =>
                       {
                           options.SetClientId("c4ade52327b01ddacff3")
                                  .SetClientSecret("da6bed851b75e317bf6b2cb67013679d9467c122")
                                  .SetRedirectUri("https://localhost:44381/callback/login/github");
                       })
                       .UseGoogle(options =>
                       {
                           options.SetClientId("1016114395689-kgtgq2p6dj27d7v6e2kjkoj54dgrrckh.apps.googleusercontent.com")
                                  .SetClientSecret("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")
                                  .SetRedirectUri("https://localhost:44381/callback/login/google")
                                  .AddScopes(Scopes.Profile);
                       })
                       .UseReddit(options =>
                       {
                           options.SetClientId("vDLNqhrkwrvqHgnoBWF3og")
                                  .SetClientSecret("Tpab28Dz0upyZLqn7AN3GFD1O-zaAw")
                                  .SetRedirectUri("https://localhost:44381/callback/login/reddit");
                       })
                       .UseTwitter(options =>
                       {
                           options.SetClientId("bXgwc0U3N3A3YWNuaWVsdlRmRWE6MTpjaQ")
                                  .SetClientSecret("VcohOgBp-6yQCurngo4GAyKeZh0D6SUCCSjJgEo1uRzJarjIUS")
                                  .SetRedirectUri("https://localhost:44381/callback/login/twitter")
                                  .AddScopes("offline.access");
                       });
            });

        services.AddHttpClient();

        services.AddControllersWithViews();

        // Register the worker responsible for creating the database used to store tokens.
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();

        app.UseStaticFiles();

        app.UseStatusCodePagesWithReExecute("/error");

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(options =>
        {
            options.MapControllers();
            options.MapDefaultControllerRoute();
        });
    }
}
