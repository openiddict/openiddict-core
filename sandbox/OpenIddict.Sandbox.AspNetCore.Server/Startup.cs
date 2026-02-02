using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Sandbox.AspNetCore.Server.Models;
using OpenIddict.Sandbox.AspNetCore.Server.Services;
using Quartz;
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
                // Enable the endpoints that will be used by the client applications.
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetDeviceAuthorizationEndpointUris("connect/device")
                       .SetEndSessionEndpointUris("connect/endsession")
                       .SetEndUserVerificationEndpointUris("connect/verify")
                       .SetIntrospectionEndpointUris("connect/introspect")
                       .SetPushedAuthorizationEndpointUris("connect/par")
                       .SetRevocationEndpointUris("connect/revoke")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserInfoEndpointUris("connect/userinfo");

                // Enable the flows that will be used by the client applications.
                options.AllowAuthorizationCodeFlow()
                       .AllowDeviceAuthorizationFlow()
                       .AllowHybridFlow()
                       .AllowImplicitFlow()
                       .AllowNoneFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow()
                       .AllowTokenExchangeFlow();

                // Register the public scopes that will be exposed by the configuration endpoint.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "demo_api");

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options.UseAspNetCore()
                       .EnableStatusCodePagesIntegration()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableEndSessionEndpointPassthrough()
                       .EnableEndUserVerificationEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserInfoEndpointPassthrough();

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

#if SUPPORTS_KESTREL_TLS_HANDSHAKE_CALLBACK_OPTIONS
                // Enable both tls_client_auth and self_signed_tls_client_auth to allow clients
                // to authenticate using either PKI certificates or self-signed certificates.
                //
                // Note: PKI and self-signed certificate authentication can be enabled independently.
                options.EnablePublicKeyInfrastructureClientCertificateAuthentication(
                [
                    // Root certificate:
                    X509Certificate2.CreateFromPem($"""
                        -----BEGIN CERTIFICATE-----
                        MIIE7jCCAtagAwIBAgIJAN+SZB+xc7usMA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
                        BAMTB1Jvb3QgQ0EwIBcNMjYwMjAxMTQxNDQzWhgPMjEyNjAyMDIxNDE0NDNaMBIx
                        EDAOBgNVBAMTB1Jvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
                        AQC68DOD6IvsJM0mc7n8bYeNaVe8e0ytJCJozdMPNXAe80vMPP4cVUPFvJ/tbSjX
                        yhREJ9xz2dYgQAhWCaTnEHY4AaE1Tj2rYqotenDQxs18qqaqoZlcaFfkRUPHRH3Q
                        iS8D8gbxzlYkjxNsfDJRi0cXFxr4wb4FmSP4ES2DFWWAWbN9wt7Tb2uDiHkjSefZ
                        Pni5F6fN6nE7wgGMYrdrCiiwJf7jEZiIZ60bsiUnJ5VUX6g4ob469CLocH/q/9Yr
                        Dad9/+YYp6SuHZilsPmW4X0fziuF/RvtsRLw4bw5jwj69KH3Y0jqUMQoyzz2CIJz
                        cDMB/MLREgcT9jTVB/M5Pl61DCzR/0d4t6RENpkNqpAIVM0Unp0nDuHPwjoeEZn3
                        vSvUiGpiYY355GaSl05OE3SOKoRHt4lBXvY43y8fRBMOwlNHYn4eO3ZDuzZYzhfs
                        68ywK4zUy47Qyn1BgNNqc/KC7kzxeLFxqTg2VJgBeXuJfucwzhOFqkOSfpeIGDK9
                        8MODFlA3usf5LXxQ7DJhkeBgPkW56BUlYVkenm9ORWe77GnoXL95p2HQUEXATHir
                        unXFPVcHET6hyegvc9AzSTZFQL4RMO3ZV5ESs+JF/YY4ycBc1+WYy2kAuP5sfsGn
                        mpeKf2Dv9MGFcDxU7iimeM92n7t5lbCRlX8NUaYeQ8jKgQIDAQABo0UwQzASBgNV
                        HRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUyHIqQnw/
                        x6e92OuJ+y+e0LSKSqQwDQYJKoZIhvcNAQELBQADggIBACCOjX4+RyoZt9tVoKdT
                        uGFoEJUGBUfcYaMdqiDstuSoNrqZXHnilzj33ZbNqj6X6rS1w5qVnkj7ZY4Wu8MP
                        Sj85Wp9cq0jMv3NfPZfKmJd2K7favGQKvgSPptSl9VgcIrpRam9BG2db1IP053tf
                        ydBB3w/yI7MTb4fkPqLWtKcuPPM8t9SsxAlKhEm+gbNEsqDX9ZIfxolHEpL2zLOi
                        a4v7+SlJdVBfo4mj+iLUeZXFRPglAnPQ3CZngfbPsjEklpOCU1v8TnhHwV8jyCgl
                        oLAceLjdlXHWVfhKU+N0jdAt8V2NPxq+yJ/gPX+J3YOrYRCHMdQZ/OFEUhmkxHNp
                        UUPkL1VJ9c8ZW2/gszFPyvsh7GHwl43y7bN8doiQVOSj6jZ7uCkQl1oz731fl97b
                        FqKVyGGx6UUEi57YS7mWsY02qNvYSObOxhSNusX/Ct06XbXS1Pn+co/3FMGMcEVf
                        IwzboV61sMqRu4l3YD0Z1AxdhXFERMlHBYyyj8CQYIXtnCUoeT40IIR3aFmEG5u8
                        /lwehTnV4slDDMJMFSW54aENpT1XP4b8m46kioNhxN+7ukdcWnYoapePuiDRboA3
                        GwRExwFUDiGO8zpnyvV4JTIGu9MZi51O3RbSlIDDhyzFsdQW3PeztwGjZWZAXD+7
                        qIoAaBbG/12cvNeZH7L9Mcpo
                        -----END CERTIFICATE-----
                        """),

                    // Intermediate certificate (optional):
                    X509Certificate2.CreateFromPem($"""
                        -----BEGIN CERTIFICATE-----
                        MIIFQzCCAyugAwIBAgIQb6sP8aiPyzYFX0lET/XJOzANBgkqhkiG9w0BAQsFADAS
                        MRAwDgYDVQQDEwdSb290IENBMCAXDTI2MDIwMTE0MTQ0M1oYDzIxMjYwMjAyMTQx
                        NDQzWjAaMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0EwggIiMA0GCSqGSIb3DQEB
                        AQUAA4ICDwAwggIKAoICAQCfObzu9v5dfio8kCCKpb0vLXUrilcOM6FGVx50rPtc
                        MjlHNG4GpghoLXjJxrUIsoeGdsCI6W+K3R+5PRlEsbCT3l/0n2/ixW3rN9rO3FOt
                        VGOHYrE2wI+i1aWP1/w/0bcCbH1J6PLKPv5syzhWWdkoTy2K72gye5Kx3zXkFQoC
                        uBFMvj3HBgmTngaDRTT1QGsRSlhuvoEiHHAvgoTfYt7bgbRhM5I5upEbXB0cucj7
                        Ghzws5R2/4qsr/QorwA8l6aNeb1dm0uB+FlMVlGelYMZ76+SjBs1rOxD0qt82h13
                        BYPBR4gLvNFafOEskFndeP3OkNaQ6kPm+uClj5OxwONnBcy7neJPqZGMtxpApLK3
                        reK3IZ/ieg1nY9zZ7OkqIzQDt1CeCBQWU3RkpEtVojkRDLCmg+pKSjHtLxUUGiQ3
                        UHrXO2Yrej8Qpx4JHdKGUfku25r4SSaj2YF61ZIvsDxlOMROfJUFbpQdyAtQPCCq
                        zpfkVKaCeCiTlifI6AZODngc9c8U+s7vLxjucz/Q4gNHwcgg/mASbjh8A2hYsbW6
                        qeg7lE9k5t6Lv820FudjfgFiq7k+zIbNsDNy3Y7CSsgBHQQSyNFngg25PPQOon9c
                        yd3PiFK36OzktnRkcTs98i3fwO2+3pp6qgOSk1Sdx877egszMjBPFzxrBX9CXIpM
                        yQIDAQABo4GKMIGHMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEG
                        MB0GA1UdDgQWBBThFsFtfMN62ev+YiMAAddufdjpRzBCBgNVHSMEOzA5gBTIcipC
                        fD/Hp73Y64n7L57QtIpKpKEWpBQwEjEQMA4GA1UEAxMHUm9vdCBDQYIJAN+SZB+x
                        c7usMA0GCSqGSIb3DQEBCwUAA4ICAQA6sBGs28FWhKgh6TxZ6U8Lc+iCdc4c9PeM
                        L5pQQosHekT0oBJK8WdvyXZS95Fz2ddJaKiiQyUKSP4XHpxE+6tBt8OOV0LJJxnx
                        yKTBZtcSiOFssu2j6aqx3oMotRZJrhuI/5ChExaPwFT1W7aQDIY6lN2KcQ/xndbX
                        Nts/2nwCvlplfiOGM7XrRMU8b4X+AVWXSksvLXiByrDh9W6WGDsBHyu+FKQVnwmW
                        QVnshKpwxIsW25JDOhFE8+VHn6yciUKUTqnCFt5HjZpZh00q8hhmlhrNBEdkxA8N
                        OF7S1uWWftJywqq23qG6pGIDQ1r1dwNzgaeNhmW6QKm2zBXUmuOW//Xt+1wtHrly
                        bDjXKKSa/zhR9plYPdvGe9PopXwTw/fQWRYcxML6aH+WbWY9AgCHFgY56YCJYZd9
                        eUIfrvPVJLn8fqwLmsWQtIY+XkAS/YQ4wTQs0zZS3+bdxeGQ6oHIMgxCDiBK8Qcc
                        RHf+RvYHiBllOJmaRaJHdsauMk9IlYYYpxPPwuWGti9B5HI4JO6bIqmR5Q8x3L/g
                        tFGMPzvWDTA2+dQcrh7WKULDH9Ngnnoodc6Hb9Iv1yCGYahcS6ARt9BzRyG1+6d9
                        bq/zCH8KQCjryiTn3ZEpsln/iXtp5nHiLegUc1OoXldrUKAz9V93l61GHUw1kdhD
                        V+KJceDj3Q==
                        -----END CERTIFICATE-----
                        """)
                ]);

                options.EnableSelfSignedClientCertificateAuthentication();

                // Note: setting a static issuer is mandatory when using mTLS aliases
                // to ensure it is not dynamically computed based on the request URI,
                // as this would result in two different issuers being used (one
                // pointing to the mTLS domain and one pointing to the regular one).
                options.SetIssuer("https://localhost:44395/");

                // Configure the mTLS endpoint aliases that will be used by client applications opting
                // for TLS-based client authentication to communicate with the authorization server:
                // the configured URIs MUST point to a domain for which the HTTPS server is configured
                // to require the use of client certificates when receiving TLS handshakes from clients.
                //
                // Using mTLS endpoint aliases is not mandatory but is strongly recommended to avoid
                // severely degrading the experience of users of browser-based clients, as TLS client
                // authentication can only be enforced globally and not per-client, which would result
                // in certificate selection prompts being systematically displayed by browsers.
                options.SetMtlsDeviceAuthorizationEndpointAliasUri("https://mtls.dev.localhost:44395/connect/device")
                       .SetMtlsIntrospectionEndpointAliasUri("https://mtls.dev.localhost:44395/connect/introspect")
                       .SetMtlsPushedAuthorizationEndpointAliasUri("https://mtls.dev.localhost:44395/connect/par")
                       .SetMtlsRevocationEndpointAliasUri("https://mtls.dev.localhost:44395/connect/revoke")
                       .SetMtlsTokenEndpointAliasUri("https://mtls.dev.localhost:44395/connect/token");
#endif
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
                //        .SetClientSecret("vVQ-yjr42sXP5VHj6AswkXuS7MU1i2gFjvJjY0TdGMk");
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

#if SUPPORTS_KESTREL_TLS_HANDSHAKE_CALLBACK_OPTIONS
        // Configure Kestrel to listen on the 44395 port and configure it to enforce mTLS.
        //
        // Note: depending on the operating system, the mtls.dev.localhost
        // subdomain MAY have to be manually mapped to 127.0.0.1 or ::1.
        services.Configure<KestrelServerOptions>(options => options.ListenAnyIP(44395, options =>
        {
            options.UseHttps(new TlsHandshakeCallbackOptions
            {
                OnConnection = GetServerAuthenticationOptionsAsync
            });
        }));

        static ValueTask<SslServerAuthenticationOptions> GetServerAuthenticationOptionsAsync(TlsHandshakeCallbackContext context)
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            return ValueTask.FromResult(new SslServerAuthenticationOptions
            {
                // Require a client certificate for all the requests pointing to the mTLS subdomain.
                ClientCertificateRequired = string.Equals(context.ClientHelloInfo.ServerName,
                    "mtls.dev.localhost", StringComparison.OrdinalIgnoreCase),

                // Ignore all the client certificate errors for requests pointing to
                // the mTLS-specific domain, even if they indicate that the chain is
                // invalid: this is necessary to allow OpenIddict to validate the PKI
                // and self-signed certificates using its own per-client chain policies.
                RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
                {
                    if (string.Equals(context.ClientHelloInfo.ServerName,
                        "mtls.dev.localhost", StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    return errors is SslPolicyErrors.None or SslPolicyErrors.RemoteCertificateNotAvailable;
                },

                // Use the same TLS server certificate as the default server instance.
                ServerCertificate = store.Certificates
                    .Find(X509FindType.FindByExtension, "1.3.6.1.4.1.311.84.1.1", validOnly: false)
                    .Cast<X509Certificate2>()
                    .OrderByDescending(static certificate => certificate.NotAfter)
                    .FirstOrDefault() ??
                    throw new InvalidOperationException("The ASP.NET Core HTTPS development certificate was not found.")
            });
        }
#endif
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
