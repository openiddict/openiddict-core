using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Sandbox.AspNetCore.Server.Models;
using OpenIddict.Sandbox.AspNetCore.Server.Services;
using Quartz;
using System.Security.Cryptography;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.Server;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddMvc();

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            // Configure the context to use Microsoft SQL Server.
            options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-aspnetcore-server.sqlite3")}");

            // Register the entity sets needed by OpenIddict.
            // Note: use the generic overload if you need
            // to replace the default OpenIddict entities.
            options.UseOpenIddict();
        });

        // Register the Identity services.
        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        // OpenIddict offers native integration with Quartz.NET to perform scheduled tasks
        // (like pruning orphaned authorizations/tokens from the database) at regular intervals.
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
                // Note: this sample uses the code flow, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableRedirectionEndpointPassthrough();

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(Startup).Assembly);

                // Register the Web providers integrations.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // URI per provider, unless all the registered providers support returning a special "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.UseWebProviders()
                       .AddGitHub(options =>
                       {
                           options.SetClientId("c4ade52327b01ddacff3")
                                  .SetClientSecret("da6bed851b75e317bf6b2cb67013679d9467c122")
                                  .SetRedirectUri("callback/login/github");
                       });
            })

            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                // Swap Issuer URL
                // swap the following lines if you need a fqdn issuer for your mobile app
                // Uri uri = new Uri("https://vsr1d2md-44349.euw.devtunnels.ms/");
                Uri uri = null;
                
                if(uri != null)
                    options.SetIssuer(uri);
                
                // ensures, that, in case an issuer uri is set and is absolute, it is used for all endpoints (for dev tunnels)
                // but the relative endpoint must be kept (for local auth via browser)
                string[] GenerateUris(Uri uri, string relative) => uri switch  {
                    null => [relative],
                    Uri {IsAbsoluteUri: false} => [relative],
                    Uri {IsAbsoluteUri: true} => [new Uri(uri, relative).ToString(), relative]
                };

                // Enable the authorization, device, introspection,
                // logout, token, userinfo and verification endpoints.
                options = options.SetAuthorizationEndpointUris(GenerateUris(uri, "connect/authorize"))
                       .SetDeviceEndpointUris(GenerateUris(uri, "connect/device"))
                       .SetIntrospectionEndpointUris(GenerateUris(uri, "connect/introspect"))
                       .SetLogoutEndpointUris(GenerateUris(uri, "connect/logout"))
                       .SetTokenEndpointUris(GenerateUris(uri, "connect/token"))
                       .SetUserinfoEndpointUris(GenerateUris(uri, "connect/userinfo"))
                       .SetVerificationEndpointUris(GenerateUris(uri, "connect/verify"))
                       .SetCryptographyEndpointUris(GenerateUris(uri, ".well-known/jwks"));

                // Note: this sample enables all the supported flows but
                // you can restrict the list of enabled flows if necessary.
                options.AllowAuthorizationCodeFlow()
                       .AllowDeviceCodeFlow()
                       .AllowHybridFlow()
                       .AllowImplicitFlow()
                       .AllowNoneFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                // Mark the "email", "profile", "roles" and "demo_api" scopes as supported scopes.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "demo_api");

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register hard-coded certificates for mobile app support
                //options.AddCertificatesForMobileApps();

                // Force client applications to use Proof Key for Code Exchange (PKCE).
                options.RequireProofKeyForCodeExchange();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserinfoEndpointPassthrough()
                       .EnableVerificationEndpointPassthrough();

                // Note: if you don't want to specify a client_id when sending
                // a token or revocation request, uncomment the following line:
                //
                // options.AcceptAnonymousClients();

                // Note: if you want to process authorization and token requests
                // that specify non-registered scopes, uncomment the following line:
                //
                // options.DisableScopeValidation();

                // Note: if you don't want to use permissions, you can disable
                // permission enforcement by uncommenting the following lines:
                //
                // options.IgnoreEndpointPermissions()
                //        .IgnoreGrantTypePermissions()
                //        .IgnoreResponseTypePermissions()
                //        .IgnoreScopePermissions();

                // Note: when issuing access tokens used by third-party APIs
                // you don't own, you can disable access token encryption:
                //
                // options.DisableAccessTokenEncryption();
            })

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // Configure the audience accepted by this resource server.
                // The value MUST match the audience associated with the
                // "demo_api" scope, which is used by ResourceController.
                options.AddAudiences("resource_server");

                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Instead of validating the token locally by reading it directly,
                // introspection can be used to ask a remote authorization server
                // to validate the token (and its attached database entry).
                //
                // options.UseIntrospection()
                //        .SetIssuer("https://localhost:44395/")
                //        .SetClientId("resource_server")
                //        .SetClientSecret("80B552BB-4CD8-48DA-946E-0815E0147DD2");
                //
                // When introspection is used, the System.Net.Http integration must be enabled.
                //
                // options.UseSystemNetHttp();

                // Register the ASP.NET Core host.
                options.UseAspNetCore();

                // For applications that need immediate access token or authorization
                // revocation, the database entry of the received tokens and their
                // associated authorizations can be validated for each API call.
                // Enabling these options may have a negative impact on performance.
                //
                // options.EnableAuthorizationEntryValidation();
                // options.EnableTokenEntryValidation();
            });

        services.AddTransient<IEmailSender, AuthMessageSender>();
        services.AddTransient<ISmsSender, AuthMessageSender>();

        // Register the worker responsible for seeding the database with the sample clients.
        // Note: in a real world application, this step should be part of a setup script.
        services.AddHostedService<Worker>();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();

        app.UseStaticFiles();

        app.UseStatusCodePagesWithReExecute("/error");

#if SUPPORTS_ENDPOINT_ROUTING
        app.UseRouting();
#endif
        app.UseRequestLocalization(options =>
        {
            options.AddSupportedCultures("en-US", "fr-FR");
            options.AddSupportedUICultures("en-US", "fr-FR");
            options.SetDefaultCulture("en-US");
        });

        app.UseAuthentication();

#if SUPPORTS_AUTHORIZATION_MIDDLEWARE
        app.UseAuthorization();
#endif

#if SUPPORTS_ENDPOINT_ROUTING
        app.UseEndpoints(options =>
        {
            options.MapControllers();
            options.MapDefaultControllerRoute();
        });
#else
        app.UseMvcWithDefaultRoute();
#endif
    }
}

internal static class ServiceCollectionExtensions
{
    
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
    internal static OpenIddictServerBuilder AddCertificatesForMobileApps(this OpenIddictServerBuilder options)
    {
        
        var privateKeyXml = "<RSAKeyValue><Modulus>uSQBwbidg8/lAw3N3xeWmc9uYQPMHH5fODGmER6uXRzzJaL8upFWXanwts7ILNFOFAWogxQuWaTqu4dUFDVuXhJsdxpT4YZy0+k8QEMyBi6VIenQtKhYgiCgx9RK6cAuXRN1X6iQ2F+3MaenUGxztEOSQ1iJarV7E5od0o0doDl0TcW/wVqnwpAc5j8K/06kICuy1Pb1glHZsF8vzCgTPwdBTAYLGbzJWWxpLNiEFDuvJR6lopSSxKpurvzYXgpZHMZuOUlmQM/XGXjCYctHldAmr+gp8/xtufx3w2/V3gApLS6kWdkA9xazLOt7Xqb2QBGNGbunVzhtGg2rBYdBXQ==</Modulus><Exponent>AQAB</Exponent><P>wiiY1qCfHaiO+FoVpB3OocUYtqI9WvXUV2tk/JIOVuBth5oRg01GMN1cMA085YcwlV1d2RQVqGXdhAKHUwyi73luFQ/yt5ehemPUQPau03Pv8GkySLSGsbwuK+FKpDQ9kdupG1eW6dBt91um4Q1Gtu+GAJ2LkucYRHA2yx6osIs=</P><Q>9BwZ5gtnMw70n/h8NvULco5RxxpfoQ++2D7iQ6rc7i27/k53E0is2L03PP/LR8bV/14z+ixMW6rH7G2d475NIzFTrR4HjZdf+i05Fq7N/xvNCLrUvAd0CWqxYrume0t9zfw62JQtp5IYQ3g9K7DxUwfY9qVwYlZByLkgrUz26rc=</Q><DP>m2n5pVte4lOpVXxudDbzzqPA+3f0WtoKBYvOgym6VqpAolmeCRcSx0x5XXFLPIMxTW42D+w2xdv8K44GmmC0D7KIfk2MwI6cUCaWoQWUvWfBORRLjs0KQDzcTH2CzNuQKS/GNj+vaitPyr9PXjfNUeN6xQVW0tkuoKGeCorZBq8=</DP><DQ>HOd26ZZQEeuja42wp5E8WcQgSsMEr719i31mrTx+DHW93M7NqqrgTImbEM348/bHQAWXgffc0r3WDlisaVsPJyugDM+RdWKHKshQCi+IlLxl+rKknd8EDlljx50QiWjW7J0BGsPw4/aYiOSj2ZiJ+prjRdExDXPJNks1Y0/JrOE=</DQ><InverseQ>g+JNJBZbKFIY5jWZxCeX7TW25KpR498x+0yGJlzCwy23JbBGDupt2tsBnhXr8KuTxSfMOGWtazQeipI//XyLCvV7BohkL6PhzMKKHwAoM/0xNaqA0d5t9Q32OqEn6I+deu4SF4OwMXkQ96xGp0zLlsWnw3HdG2rVtx5KYARMmGA=</InverseQ><D>YA+CqdT0RXQUyyTacKp4hY3PI58oxI/9L9by52cX6VAgCKMsplDKkwad0vwveLGQ5WqaKIjME88xy+NHiMTAYycECDgs1ZNA+RrHHEDBL9vznQkINPQ0GDB9u7E2vVnttHVoLR31KY9gKe9nLJ9Y2WtF9JN3mVpYZa9NUfXOLVc+zs6ChwqfryfrkgQGHZXNFtwYhG4KuOLkrQy2S4etJEWn+NMbJVYEmy1Sg99BZs4eyi0666B30ofUsx6GwyCa9IXgDm4cJnUDQu0ZEGNU7LX+p9lFym13DkWt4z9TuE3QeOSr7jHEQz1CdE8a4zsqdf3TKP2Fl05+URL35kr/MQ==</D></RSAKeyValue>";
        var rsa = RSA.Create(2048);
        rsa.FromXmlString(privateKeyXml);

        options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));
        options.AddSigningKey(new RsaSecurityKey(rsa));

        return options;
    }

}
