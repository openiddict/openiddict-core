using Microsoft.EntityFrameworkCore;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.Maui.Client;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        builder.Services.AddDbContext<DbContext>(options =>
        {
            options.UseSqlite($"Filename={Path.Combine(FileSystem.AppDataDirectory, "database.sqlite3")}");
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
                // Enable the redirection endpoint needed to handle the callback stage.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // address per provider, unless all the registered providers support returning an "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.SetRedirectionEndpointUris(
                    "/signin-local",
                    "/signin-twitter");

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the MAUI host and configure the MAUI-specific options.
                options.UseMaui()
                       .SetAuthenticationTimeout(TimeSpan.FromMinutes(2));

                // Register the System.Net.Http integration.
                options.UseSystemNetHttp();

                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://localhost:44395/", UriKind.Absolute),

                    ClientId = "maui",
                    RedirectUri = new Uri("oi-sb-maui://openiddict/signin-local", UriKind.Absolute),
                    Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
                });

                // Register the Web providers integrations.
                options.UseWebProviders()
                       .AddTwitter(new()
                       {
                           ClientId = "bXgwc0U3N3A3YWNuaWVsdlRmRWE6MTpjaQ",
                           ClientSecret = "VcohOgBp-6yQCurngo4GAyKeZh0D6SUCCSjJgEo1uRzJarjIUS",
                           RedirectUri = new Uri("oi-sb-maui://openiddict/signin-twitter", UriKind.Absolute)
                       });
            });

        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        // Note: pages must be registered in the container to be able to use constructor injection.
        builder.Services.AddSingleton<MainPage>();

        // Register the initialization service responsible for creating the Sqlite database.
        builder.Services.AddScoped<IMauiInitializeScopedService, Worker>();

        return builder.Build();
    }
}