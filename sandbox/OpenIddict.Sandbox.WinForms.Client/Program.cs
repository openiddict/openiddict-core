using System.Diagnostics;
using Dapplo.Microsoft.Extensions.Hosting.WinForms;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using OpenIddict.Client;
using OpenIddict.Sandbox.WinForms.Client;
using OpenIddict.Sandbox.WinForms.Client.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

#if NET
ApplicationConfiguration.Initialize();
#endif

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
#if NET
        services.AddDbContext<ApplicationDbContext>();
#else
        services.AddScoped<ApplicationDbContext>();
#endif

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
#if NET
                // Configure OpenIddict to use the Entity Framework Core stores and models.
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();
#else
                // Configure OpenIddict to use the Entity Framework 6.x stores and models.
                options.UseEntityFramework()
                       .UseDbContext<ApplicationDbContext>();
#endif
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
                    PostLogoutRedirectUri = new Uri("com.openiddict.sandbox.winforms.client:/callback/logout/local", UriKind.Absolute),
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
                       .AddGitHub(options =>
                       {
                           options.SetClientId("cf8efb4d76c0cb7109d3")
                                  // Note: GitHub doesn't allow creating public clients and requires using a secret. While this
                                  // is discouraged practice, it is the only option to use this provider in a desktop client.
                                  .SetClientSecret("e8c0f6b869164411bb9052e42414cbcc52d518cd")
                                  // Note: GitHub doesn't support the recommended ":/" syntax and requires using "://".
                                  .SetRedirectUri("com.openiddict.sandbox.winforms.client://callback/login/github");
                       });
            });
    })
    .ConfigureWinForms<MainForm>()
    .UseWinFormsLifetime()
    .Build();

// Before starting the host, create the database used to store the application data
// and add the registry entries required to register the custom URI scheme.
//
// Note: in a real world application, this step should be part of a setup script.
await using (var scope = host.Services.CreateAsyncScope())
{
#if NET
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();
#endif

    // Create the registry entries necessary to handle URI protocol activations.
    //
    // Note: this sample creates the entry under the current user account (as it doesn't
    // require administrator rights), but the registration can also be added globally
    // in HKEY_CLASSES_ROOT (in this case, it should be added by a dedicated installer).
    //
    // Alternatively, the application can be packaged and use windows.protocol to
    // register the protocol handler/custom URI scheme with the operating system.
    using var root = Registry.CurrentUser.CreateSubKey("SOFTWARE\\Classes\\com.openiddict.sandbox.winforms.client");
    root.SetValue(string.Empty, "URL:com.openiddict.sandbox.winforms.client");
    root.SetValue("URL Protocol", string.Empty);

    using var command = root.CreateSubKey("shell\\open\\command");
    command.SetValue(string.Empty, string.Format("\"{0}\" \"%1\"",
#if NET
        Environment.ProcessPath
#else
        Process.GetCurrentProcess().MainModule.FileName
#endif
        ));
}

await host.RunAsync();