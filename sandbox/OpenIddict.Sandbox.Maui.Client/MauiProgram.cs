using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using OpenIddict.Client;
using OpenIddict.Client.Windows;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.Maui.Client;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        builder.Services.AddDbContext<DbContext>(options =>
        {
            options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-maui-client.sqlite3")}");
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
                // Note: this sample uses the authorization code and refresh token
                // flows, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow()
                       .AllowRefreshTokenFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the Windows host.
                options.UseWindows();

                // Set the client URI that will uniquely identify this application.
                options.SetClientUri(new Uri("openiddict-sandbox-maui-client://localhost/", UriKind.Absolute));

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(MauiProgram).Assembly);

                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://localhost:44395/", UriKind.Absolute),
                    ProviderName = "Local",

                    ClientId = "maui",
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

        builder.UseMauiApp<App>()
            .ConfigureFonts(options =>
            {
                options.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                options.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        // Note: MAUI is not built on top of the .NET Generic Host and doesn't register any of
        // the services typically found in applications using the .NET Generic Host. Since these
        // services are required by the OpenIddict Windows integration to handle callbacks and
        // redirect protocol activations to the correct instance, custom implementations are
        // registered here. For more information, see https://github.com/dotnet/maui/issues/2244.

        builder.Services.AddSingleton<IHostEnvironment>(new HostingEnvironment
        {
            ApplicationName = typeof(MauiProgram).Assembly.GetName().Name!
        });

        builder.Services.AddSingleton<IHostApplicationLifetime, MauiHostApplicationLifetime>();

        builder.Services.AddSingleton<IMauiInitializeService>(provider => new MauiHostedServiceAdapter(
            ActivatorUtilities.CreateInstance<OpenIddictClientWindowsListener>(provider)));

        builder.Services.AddSingleton<IMauiInitializeService>(provider => new MauiHostedServiceAdapter(
            ActivatorUtilities.CreateInstance<OpenIddictClientWindowsService>(provider)));

        // Note: pages must be registered in the container to be able to use constructor injection.
        builder.Services.AddSingleton<MainPage>();

        // Register the initialization service responsible for creating the Sqlite database.
        builder.Services.AddScoped<IMauiInitializeScopedService, Worker>();

        return builder.Build();
    }
}