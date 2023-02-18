using Dapplo.Microsoft.Extensions.Hosting.WinForms;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;
using OpenIddict.Sandbox.WinForms.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

var host = new HostBuilder()
    // Note: applications for which a single instance is preferred can reference
    // the Dapplo.Microsoft.Extensions.Hosting.AppServices package and call this
    // method to automatically close extra instances based on the specified identifier:
    //
    // .ConfigureSingleInstance(options => options.MutexId = "{D6FEAFC8-3079-4881-B9F2-0B78EAF38B85}")
    //
    .ConfigureLogging(options => options.AddDebug())
    .ConfigureServices(services =>
    {
        services.AddDbContext<DbContext>(options =>
        {
            options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-winforms-client.sqlite3")}");
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
                options.UseSystemIntegration();

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

                    ClientId = "winforms",

                    // This sample uses protocol activations with a custom URI scheme to handle callbacks.
                    //
                    // For more information on how to construct private-use URI schemes,
                    // read https://www.rfc-editor.org/rfc/rfc8252#section-7.1 and
                    // https://www.rfc-editor.org/rfc/rfc7595#section-3.8.
                    RedirectUri = new Uri("com.openiddict.sandbox.winforms.client:/callback/login/local", UriKind.Absolute),

                    Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
                });

                // Register the Web providers integrations.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // address per provider, unless all the registered providers support returning an "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.UseWebProviders()
                       .UseGitHub()
                       .SetClientId("cf8efb4d76c0cb7109d3")
                       .SetClientSecret("e8c0f6b869164411bb9052e42414cbcc52d518cd")
                       // Note: GitHub doesn't support the recommended ":/" syntax and requires using "://".
                       .SetRedirectUri("com.openiddict.sandbox.winforms.client://callback/login/github");
            });

        // Register the worker responsible for creating the database used to store tokens
        // and adding the registry entries required to register the custom URI scheme.
        //
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();
    })
    .ConfigureWinForms<MainForm>()
    .UseWinFormsLifetime()
    .Build();

await host.RunAsync();