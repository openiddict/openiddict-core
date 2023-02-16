using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;
using OpenIddict.Sandbox.Console.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

var host = new HostBuilder()
    // Note: applications for which a single instance is preferred can reference
    // the Dapplo.Microsoft.Extensions.Hosting.AppServices package and call this
    // method to automatically close extra instances based on the specified identifier:
    //
    // .ConfigureSingleInstance(options => options.MutexId = "{802A478D-00E8-4DAE-9A27-27B31A47CB39}")
    //
    .ConfigureLogging(options => options.AddDebug())
    .ConfigureServices(services =>
    {
        services.AddDbContext<DbContext>(options =>
        {
            options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-console-client.sqlite3")}");
            options.UseOpenIddict();
        });

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFrameworkCore()
                       .UseDbContext<DbContext>();
            })

            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Note: this sample uses the authorization code and refresh token
                // flows, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow()
                       .AllowRefreshTokenFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Add the operating system integration.
                options.UseSystemIntegration()
                       .DisableActivationHandling()
                       .DisableActivationRedirection()
                       .DisablePipeServer()
                       .EnableEmbeddedWebServer()
                       .UseSystemBrowser();

                // Set the client URI that will uniquely identify this application.
                options.SetClientUri(new Uri("http://localhost/", UriKind.Absolute));

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(Program).Assembly);

                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://localhost:44395/", UriKind.Absolute),
                    ProviderName = "Local",

                    ClientId = "console",
                    RedirectUri = new Uri("callback/login/local", UriKind.Relative),
                    Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
                });

                // Register the Web providers integrations.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // address per provider, unless all the registered providers support returning an "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.UseWebProviders()
                       .UseTwitter()
                       .SetClientId("bXgwc0U3N3A3YWNuaWVsdlRmRWE6MTpjaQ")
                       .SetClientSecret("VcohOgBp-6yQCurngo4GAyKeZh0D6SUCCSjJgEo1uRzJarjIUS")
                       .SetRedirectUri(new Uri("callback/login/twitter", UriKind.Relative));
            });

        // Register the worker responsible for creating the database used to store tokens
        // and adding the registry entries required to register the custom URI scheme.
        //
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();

        // Register the background service responsible for handling the console interactions.
        services.AddHostedService<InteractiveService>();
    })
    .UseConsoleLifetime()
    .Build();

await host.RunAsync();