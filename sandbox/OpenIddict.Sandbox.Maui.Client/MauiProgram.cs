using System.Net.Http;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Client.SystemIntegration;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.Maui.Client;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        builder.Logging.AddDebug();

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

                // remove DevelopmentSigning/Encryption certificates and uncomment the following line if you run on iOS or Android
                // options.AddCertificatesForMobileApps();

                // Register the operating system integration.
                options.UseSystemIntegration();

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(MauiProgram).Assembly)
#if IOS
                       // Warning: server certificate validation is disabled to simplify testing the MAUI
                       // application with the iOS simulator: in production, it SHOULD NEVER be disabled.
                       .ConfigureHttpClientHandler("Local", handler => handler.ServerCertificateCustomValidationCallback =
                           HttpClientHandler.DangerousAcceptAnyServerCertificateValidator)
#endif
                       ;

                // Add a client registration matching the client application definition in the server project.
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri("https://vsr1d2md-44349.euw.devtunnels.ms/", UriKind.Absolute),
                    ProviderName = "Local",

                    ClientId = "maui",

                    // This sample uses protocol activations with a custom URI scheme to handle callbacks.
                    //
                    // For more information on how to construct private-use URI schemes,
                    // read https://www.rfc-editor.org/rfc/rfc8252#section-7.1 and
                    // https://www.rfc-editor.org/rfc/rfc7595#section-3.8.
                    PostLogoutRedirectUri = new Uri("com.openiddict.sandbox.maui.client:/callback/logout/local", UriKind.Absolute),
                    RedirectUri = new Uri("com.openiddict.sandbox.maui.client:/callback/login/local", UriKind.Absolute),

                    Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
                });

                // Register the Web providers integrations.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // address per provider, unless all the registered providers support returning an "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.UseWebProviders()
                       .AddTwitter(options =>
                       {
                           options.SetClientId("bXgwc0U3N3A3YWNuaWVsdlRmRWE6MTpjaQ")
                                   // Note: Twitter doesn't support the recommended ":/" syntax and requires using "://".
                                  .SetRedirectUri("com.openiddict.sandbox.maui.client://callback/login/twitter");
                       });
            });

        builder.UseMauiApp<App>()
            .ConfigureFonts(options =>
            {
                options.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                options.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        // Note: MAUI is not built on top of the .NET Generic Host and doesn't register any of
        // the services typically found in applications using the .NET Generic Host. Since these
        // services are required by the OpenIddict client system integration to handle callbacks
        // and redirect protocol activations to the correct instance, custom implementations are
        // registered here. For more information, see https://github.com/dotnet/maui/issues/2244.

        builder.Services.AddSingleton<IHostEnvironment>(new HostingEnvironment
        {
            ApplicationName = typeof(MauiProgram).Assembly.GetName().Name!
        });

        builder.Services.AddSingleton<IHostApplicationLifetime, MauiHostApplicationLifetime>();

        builder.Services.AddSingleton<IMauiInitializeService>(static provider => new MauiHostedServiceAdapter(
            ActivatorUtilities.CreateInstance<OpenIddictClientSystemIntegrationActivationHandler>(provider)));

        builder.Services.AddSingleton<IMauiInitializeService>(static provider => new MauiHostedServiceAdapter(
            ActivatorUtilities.CreateInstance<OpenIddictClientSystemIntegrationHttpListener>(provider)));

        builder.Services.AddSingleton<IMauiInitializeService>(static provider => new MauiHostedServiceAdapter(
            ActivatorUtilities.CreateInstance<OpenIddictClientSystemIntegrationPipeListener>(provider)));

        // Note: pages must be registered in the container to be able to use constructor injection.
        builder.Services.AddSingleton<MainPage>();

        // Register the initialization service responsible for creating the SQLite database.
        builder.Services.AddScoped<IMauiInitializeScopedService, Worker>();

        return builder.Build();
    }
    
    /// <summary>
    ///     Note: Do not use the following keys in production!
    ///     there just added so we can authenticate from Android (Maui/Avalonia), iOS (Maui/Avalonia) and Macos, since on these platforms the following does not work
    ///     
    ///       options.AddDevelopmentEncryptionCertificate()
    ///         .AddDevelopmentSigningCertificate();
    ///     
    ///     this is because
    ///     1. Adding an X509 certificate to the system store is not supported (throws on iOS and Android)
    ///     2. and even if so, it would be a different machine - therefore different store - and client and server would not use the same certificate!
    /// </summary>
    /// <param name="options"></param>
    /// <returns></returns>
    private static OpenIddictClientBuilder AddCertificatesForMobileApps(this OpenIddictClientBuilder options)
    {
        var privateKeyXml = "<RSAKeyValue><Modulus>uSQBwbidg8/lAw3N3xeWmc9uYQPMHH5fODGmER6uXRzzJaL8upFWXanwts7ILNFOFAWogxQuWaTqu4dUFDVuXhJsdxpT4YZy0+k8QEMyBi6VIenQtKhYgiCgx9RK6cAuXRN1X6iQ2F+3MaenUGxztEOSQ1iJarV7E5od0o0doDl0TcW/wVqnwpAc5j8K/06kICuy1Pb1glHZsF8vzCgTPwdBTAYLGbzJWWxpLNiEFDuvJR6lopSSxKpurvzYXgpZHMZuOUlmQM/XGXjCYctHldAmr+gp8/xtufx3w2/V3gApLS6kWdkA9xazLOt7Xqb2QBGNGbunVzhtGg2rBYdBXQ==</Modulus><Exponent>AQAB</Exponent><P>wiiY1qCfHaiO+FoVpB3OocUYtqI9WvXUV2tk/JIOVuBth5oRg01GMN1cMA085YcwlV1d2RQVqGXdhAKHUwyi73luFQ/yt5ehemPUQPau03Pv8GkySLSGsbwuK+FKpDQ9kdupG1eW6dBt91um4Q1Gtu+GAJ2LkucYRHA2yx6osIs=</P><Q>9BwZ5gtnMw70n/h8NvULco5RxxpfoQ++2D7iQ6rc7i27/k53E0is2L03PP/LR8bV/14z+ixMW6rH7G2d475NIzFTrR4HjZdf+i05Fq7N/xvNCLrUvAd0CWqxYrume0t9zfw62JQtp5IYQ3g9K7DxUwfY9qVwYlZByLkgrUz26rc=</Q><DP>m2n5pVte4lOpVXxudDbzzqPA+3f0WtoKBYvOgym6VqpAolmeCRcSx0x5XXFLPIMxTW42D+w2xdv8K44GmmC0D7KIfk2MwI6cUCaWoQWUvWfBORRLjs0KQDzcTH2CzNuQKS/GNj+vaitPyr9PXjfNUeN6xQVW0tkuoKGeCorZBq8=</DP><DQ>HOd26ZZQEeuja42wp5E8WcQgSsMEr719i31mrTx+DHW93M7NqqrgTImbEM348/bHQAWXgffc0r3WDlisaVsPJyugDM+RdWKHKshQCi+IlLxl+rKknd8EDlljx50QiWjW7J0BGsPw4/aYiOSj2ZiJ+prjRdExDXPJNks1Y0/JrOE=</DQ><InverseQ>g+JNJBZbKFIY5jWZxCeX7TW25KpR498x+0yGJlzCwy23JbBGDupt2tsBnhXr8KuTxSfMOGWtazQeipI//XyLCvV7BohkL6PhzMKKHwAoM/0xNaqA0d5t9Q32OqEn6I+deu4SF4OwMXkQ96xGp0zLlsWnw3HdG2rVtx5KYARMmGA=</InverseQ><D>YA+CqdT0RXQUyyTacKp4hY3PI58oxI/9L9by52cX6VAgCKMsplDKkwad0vwveLGQ5WqaKIjME88xy+NHiMTAYycECDgs1ZNA+RrHHEDBL9vznQkINPQ0GDB9u7E2vVnttHVoLR31KY9gKe9nLJ9Y2WtF9JN3mVpYZa9NUfXOLVc+zs6ChwqfryfrkgQGHZXNFtwYhG4KuOLkrQy2S4etJEWn+NMbJVYEmy1Sg99BZs4eyi0666B30ofUsx6GwyCa9IXgDm4cJnUDQu0ZEGNU7LX+p9lFym13DkWt4z9TuE3QeOSr7jHEQz1CdE8a4zsqdf3TKP2Fl05+URL35kr/MQ==</D></RSAKeyValue>";
        var rsa = RSA.Create(2048);
        rsa.FromXmlString(privateKeyXml);

        options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));
        options.AddSigningKey(new RsaSecurityKey(rsa));

        return options;
    }

}
