using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using OpenIddict.Sandbox.Console.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = Host.CreateApplicationBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddDebug();

builder.Services.AddDbContext<DbContext>(options =>
{
    options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-console-client.sqlite3")}");
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()

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
        // Note: this sample enables all the supported flows but
        // you can restrict the list of enabled flows if necessary.
        options.AllowAuthorizationCodeFlow()
               .AllowClientCredentialsFlow()
               .AllowDeviceAuthorizationFlow()
               .AllowHybridFlow()
               .AllowImplicitFlow()
               .AllowNoneFlow()
               .AllowPasswordFlow()
               .AllowRefreshTokenFlow()
               .AllowTokenExchangeFlow();

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
               .UseSystemBrowser()
               .SetApplicationDiscriminator("0XP3WQ07VVMCVBJ")
               .SetAllowedEmbeddedWebServerPorts(49152, 49153, 49154);

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
            ProviderDisplayName = "Local authorization server",

            ClientId = "console",

            PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative),
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
               .AddGitHub(options =>
               {
                   options.SetClientId("992372d088f8676a7945")
                          // Note: GitHub doesn't allow creating public clients and requires using a secret. While this
                          // is a discouraged practice, it is the only option to use this provider in a desktop client.
                          .SetClientSecret("1f18c22f766e44d7bd4ea4a6510b9e337d48ab38")
                          .SetRedirectUri("callback/login/github");
               })
               // Note: Google requires using separate client registrations to be able to use the authorization code flow
               // and device flow in the same application. To work around this limitation, two registrations are used but
               // each one explicitly restricts the grant types that OpenIddict is allowed to negotiate dynamically.
               .AddGoogle(options =>
               {
                   options.SetClientId("1016114395689-arf09f1g51hadci5p5hn6lpp798k8rql.apps.googleusercontent.com")
                          // Note: Google doesn't allow creating public clients and requires using a secret. While this
                          // is discouraged practice, it is the only option to use this provider in a desktop client.
                          .SetClientSecret("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")
                          .SetRedirectUri("callback/login/google")
                          .SetAccessType(OpenIddictClientWebIntegrationConstants.Google.AccessTypes.Offline)
                          .AddScopes(Scopes.Profile)
                          .AddGrantTypes(GrantTypes.AuthorizationCode)
                          .SetProviderName("Google [code flow]")
                          .SetProviderDisplayName("Google (authorization code grant-only)");
               })
               .AddGoogle(options =>
               {
                   options.SetClientId("1016114395689-le5kvnikv5hhg3otvn1tgs2aogpkpvff.apps.googleusercontent.com")
                          .SetClientSecret("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")
                          .SetRedirectUri("callback/login/google")
                          .SetAccessType(OpenIddictClientWebIntegrationConstants.Google.AccessTypes.Offline)
                          .AddScopes(Scopes.Profile)
                          .AddGrantTypes(GrantTypes.DeviceCode)
                          .SetProviderName("Google [device flow]")
                          .SetProviderDisplayName("Google (device code grant-only)");
               })
               .AddTwitter(options =>
               {
                   options.SetClientId("bXgwc0U3N3A3YWNuaWVsdlRmRWE6MTpjaQ")
                          .SetRedirectUri("callback/login/twitter");
               });
    });

// Register the background service responsible for handling the console interactions.
builder.Services.AddHostedService<InteractiveService>();

var app = builder.Build();

// Before starting the host, create the database used to store the application data.
//
// Note: in a real world application, this step should be part of a setup script.
await using (var scope = app.Services.CreateAsyncScope())
{
    var context = scope.ServiceProvider.GetRequiredService<DbContext>();
    await context.Database.EnsureCreatedAsync();
}

await app.RunAsync();
