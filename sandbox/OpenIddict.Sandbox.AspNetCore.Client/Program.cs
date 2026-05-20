using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Client.WebIntegration;
using OpenIddict.Sandbox.AspNetCore.Client.Models;
using Quartz;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlite($"Filename={Path.Combine(Path.GetTempPath(), "openiddict-sandbox-aspnetcore-client.sqlite3")}");
    options.UseOpenIddict();
});

builder.Services.AddAuthentication(options =>
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
builder.Services.AddQuartz(options =>
{
    options.UseSimpleTypeLoader();
    options.UseInMemoryStore();
});

// Register the Quartz.NET service and configure it to block shutdown until jobs are complete.
builder.Services.AddQuartzHostedService(options => options.WaitForJobsToComplete = true);

builder.Services.AddOpenIddict()

    // Register the OpenIddict core components.
    .AddCore(options =>
    {
        // Configure OpenIddict to use the Entity Framework Core stores and models.
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
        // Note: this sample uses the authorization code and refresh token
        // flows, but you can enable the other flows if necessary.
        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow();

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
               .SetProductInformation(typeof(Program).Assembly);

        // Add a client registration matching the client application definition in the server project.
        options.AddRegistration(new OpenIddictClientRegistration
        {
            Issuer = new Uri("https://localhost:44395/", UriKind.Absolute),
            ProviderName = "Local",
            ProviderDisplayName = "Local OIDC server",

            ClientId = "mvc",
            Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" },

            RedirectUri = new Uri("callback/login/local", UriKind.Relative),
            PostLogoutRedirectUri = new Uri("callback/logout/local", UriKind.Relative),

            // ClientSecret = "emCimpdc9SeOaZzN5jzm4_eek-STF6VenfVlKO1_qt0",
            //
            // On supported platforms, this application can authenticate using 3 different client
            // authentication methods that all offer a higher security level than shared client secrets:
            //
            //   1) tls_client_auth (PKI-based mutual TLS authentication): while it requires
            //      setting up a proper Public Key Infrastructure, this method offers a very
            //      high level of security, as the authorization server never has access to the
            //      private key used by the client to authenticate itself and can dynamically check
            //      the revocation status of the client certificate using standard PKI mechanisms.
            //
            //   2) self_signed_tls_client_auth (self-signed certificate-based mutual TLS authentication):
            //      this method is easier to deploy than PKI-based mutual TLS authentication, while
            //      still offering a high level of security. Unlike PKI-based mutual TLS authentication,
            //      the revocation status of the client certificate is never checked but certificates can
            //      be "revoked" by being removed from the JSON Web Key Set associated with the client.
            //
            //   3) private_key_jwt (JWT client assertions signed with a private key): while this
            //      method doesn't offer the same security guarantees as mutual TLS authentication,
            //      it is more secure than shared secrets and doesn't have the operational constraints
            //      required by the two mutual TLS methods described above (such as TLS configuration).
            //
            // The actual client authentication method used by the OpenIddict client is automatically
            // selected based on the registered credentials and the methods supported by the server:
            // when supported by the server, mutual TLS authentication methods are always preferred.
            //
            // In all cases, no client secret is necessary but the client needs to be able to access the
            // private key of the certificate/key to be able to generate and sign the client assertions.

            SigningCredentials =
            {
                // Note: this certificate can be used with either tls_client_auth or private_key_jwt,
                // depending on the server configuration (and the client authentication methods explicitly
                // configured via OpenIddictClientRegistration.ClientAuthenticationMethods, if applicable).
                //
                GetPublicKeyInfrastructureCertificate(),

                // Note: this certificate can be used with either self_signed_tls_client_auth or private_key_jwt,
                // depending on the server configuration (and the client authentication methods explicitly
                // configured via OpenIddictClientRegistration.ClientAuthenticationMethods, if applicable):
                //
                // GetSelfSignedCertificate(),

                // Note: this key can only be used with private_key_jwt as raw keys cannot be used with TLS.
                // GetSigningKey()
            }
        });

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
               })
               .AddGoogle(options =>
               {
                   options.SetClientId("1016114395689-kgtgq2p6dj27d7v6e2kjkoj54dgrrckh.apps.googleusercontent.com")
                          .SetClientSecret("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")
                          .SetRedirectUri("callback/login/google")
                          .SetAccessType(OpenIddictClientWebIntegrationConstants.Google.AccessTypes.Offline)
                          .AddScopes(Scopes.Profile);
               })
               .AddReddit(options =>
               {
                   options.SetClientId("vDLNqhrkwrvqHgnoBWF3og")
                          .SetClientSecret("Tpab28Dz0upyZLqn7AN3GFD1O-zaAw")
                          .SetRedirectUri("callback/login/reddit")
                          .SetDuration(OpenIddictClientWebIntegrationConstants.Reddit.Durations.Permanent);
               });
    });

// Register a named HTTP client that will be used to call the demo resource API.
//
// Note: since the authorization server is configured to issue certificate-bound
// access tokens, the client certificate MUST be attached to outgoing HTTP requests
// and the mTLS subdomain (for which TLS client authentication is enabled) MUST be used.
builder.Services.AddHttpClient("ApiClient")
    .AddAsKeyed()
    .ConfigureHttpClient(static client => client.BaseAddress = new Uri("https://mtls.dev.localhost:44395/"))
    .ConfigurePrimaryHttpMessageHandler(static () => new HttpClientHandler
    {
        ClientCertificateOptions = ClientCertificateOption.Manual,
        ClientCertificates = { GetPublicKeyInfrastructureCertificate().Certificate }
    });

builder.Services.AddMvc();

var app = builder.Build();

app.UseDeveloperExceptionPage();

app.UseStaticFiles();

app.UseStatusCodePagesWithReExecute("/error");
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapDefaultControllerRoute();

// Before starting the host, create the database used to store the application data.
//
// Note: in a real world application, this step should be part of a setup script.
await using (var scope = app.Services.CreateAsyncScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();
}

await app.RunAsync();

static X509SigningCredentials GetPublicKeyInfrastructureCertificate()
{
    // Note: OpenIddict only negotiates PKI-based or self-signed mutual
    // TLS authentication if the certificate explicitly contains the
    // "digitalSignature" key usage and the "clientAuth" extended key usage.
    var certificate = X509Certificate2.CreateFromPem(
        certPem: $"""
            -----BEGIN CERTIFICATE-----
            MIIEezCCAmOgAwIBAgIRALTZE9ezjPCWDFr38cp6AMAwDQYJKoZIhvcNAQELBQAw
            GjEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMCAXDTI2MDIwMTE0MTQ0M1oYDzIx
            MjYwMjAyMTQxNDQzWjAaMRgwFgYDVQQDEw9FbmQgY2VydGlmaWNhdGUwggEiMA0G
            CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMs9spnvKeKw6VwPbpB47ikC6bL0Cn
            S+K19Fp8dJg8b4dA1J1Y8dA2gi2nU/+ntOMYp1A6EvMZ8UpbgnSmhUN/2JQFU5Hc
            PP0/IMjZAl2Iseh2yiK3Ril4Agbng6YW7e9P5YtMV+6i/stYujwNTXsUMr/+QSUI
            Nze7856XSIl9gRjWEKJ17Jk/tJpun/zdpl4hXcptrsxxLU/E03bC3LcjiXzg8/Zl
            3/oEHqcHfv9C8RTdIBBw66zJAYzGfxwV31cJ9QQ2udlipi2l+ZR6jFWzzJI4XmiC
            FzdwZRvhMLJsyK5miVIl0qPp3zJ2IyEb/2pLA0bc/ylZwVq6Z49k2xhZAgMBAAGj
            gbkwgbYwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAww
            CgYIKwYBBQUHAwIwHQYDVR0OBBYEFHPamNF/deBBv5JpDwiiRctPw4ziMEkGA1Ud
            IwRCMECAFOEWwW18w3rZ6/5iIwAB12592OlHoRakFDASMRAwDgYDVQQDEwdSb290
            IENBghBvqw/xqI/LNgVfSURP9ck7MBQGA1UdEQQNMAuCCWxvY2FsaG9zdDANBgkq
            hkiG9w0BAQsFAAOCAgEAbBq73JzDpK11hoRUxHq7LvplQEe/FNuD/slvn9Crfm2d
            jJj0HsQQZpMgxP7SZ9FNvFqCo+/dm9PchIlwqwSjWtTxgYmcMOXw0Rzst85Ug4U1
            I2PG6iPxJ4WLSW2gzo//jFPa7MD1AnqDYwcCQTVsQW6aJavY3mFD31SJKsvSKqsV
            6xTXsajLRetCSXGe5qFgfyLC9tOhtTWXsCed/ISoQ9bljhOSqT6pxkpOVu0AHHMB
            1CMZay/B5ecjb66mwSoRcAPweMlAYJkjU5HXHSi7kB3gRQTsb1ZymEn67Q4C5cpI
            Lq6UFK5bWZf1A0kFbYJBmn3oHsWxMQqv0F6QE7r4Mg6pfk9swzYZ8WqcgjiGHQET
            pVU7ZKkUsg2JREXxRnhh5+Q+vGsF/DjhzQ6NrfPm8sqs+X+LzUN2cne8ZPclfyW2
            VKCHTPZ6o8mELiAlIPdBYUYsgUEOsfmUWbx4wfx5IB7vnenrenInLLyGOOCxR33d
            o/gDMLFdeKHXK2ISsbDCk+zwEF8kztn1cXWK+K6H9cr8oJjDi1OJwTkqz9msar+9
            mjZ1CPAF0X+mLgrhVnNYqd5oqeeLerXKkAvpC2TgvlWJRGyDILhjva3J+2fQAYXZ
            +OKFHNPf3n8Co4s5TMr1eiGVtS1etH6hPxnn5Jwnes9JZWFRLcjeTmPLSRWFucg=
            -----END CERTIFICATE-----
            """,
        keyPem: $"""
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEAzLPbKZ7ynisOlcD26QeO4pAumy9Ap0vitfRafHSYPG+HQNSd
            WPHQNoItp1P/p7TjGKdQOhLzGfFKW4J0poVDf9iUBVOR3Dz9PyDI2QJdiLHodsoi
            t0YpeAIG54OmFu3vT+WLTFfuov7LWLo8DU17FDK//kElCDc3u/Oel0iJfYEY1hCi
            deyZP7Sabp/83aZeIV3Kba7McS1PxNN2wty3I4l84PP2Zd/6BB6nB37/QvEU3SAQ
            cOusyQGMxn8cFd9XCfUENrnZYqYtpfmUeoxVs8ySOF5oghc3cGUb4TCybMiuZolS
            JdKj6d8ydiMhG/9qSwNG3P8pWcFaumePZNsYWQIDAQABAoIBACorfyHC4d5dpmKJ
            XxRAf1oDM+a6REpyoqCzVxS+fEIvA6ECa+vP3QHtrXQEJO2qoQIKLcfY8YXNpHDX
            nipT18T1nADA55KEafNgUKAMEbLAW9Bk8ePpq09Ss5NsFoIwwBUoh5rRnpKrhL6h
            lw9yf8F4dv7s8rEPlwa8OFaYFeLpoBLsPaX3nMu45CKb25dFZzSv9ORVs28LALrS
            oK9MbtNFkmf/4EmpYA+nblkZd2bu4BomOF7C2F4bwtikN29vl4NPMhlbZGTy1hm9
            jzMOOvO1DwvIjHRVcfHKMDZ7cw1Pj5TmeApToSs6ygu1lce0GQcNVm+KV2qZMjNQ
            Al6cdFUCgYEA7HZ6wvZU/WA7ei+jIwrJdyQQ3jU/LAu7GGhXiMU3z2RSR/vieY5R
            4IjQOgUkLBuQcy9uoQcSLpH/SNLIi6qhlMBvZuHq9QKF60t68tuW0PFSoa+SKaEn
            DCZ70bnxo4OSRUtrzxikYHnwOvRGEli4EAOENETaQBKJUUygov/pOWMCgYEA3Z2a
            TJlptRq75G6LHZvbBBzZdG9Mr04O6zvh5TGsJW86b6ov9BTAGz6Z37KWR1yUDfyH
            dqNf90kJ8hs1eO6gGDQyGaH9yerrlULukANQfvpC0rEeJ7DfXSc1iLa3Q6+AOt5v
            9TkQY7s/47iOPoCmblZ4FeVcIMx88ms2mBRXshMCgYAN9pkdNiqio7Ifbvy1Lwfi
            jzCnzoEierbbpB23J9450vTA53DiOLNBDRMuuer+58nJ430m6SH7ugdXJ4tMJBFS
            lWJ+ssyLF1ENKfHisXDgeb+laJa6+pcxsnwRUGeifjx+9wswuYXLZKf48z/ICZEk
            8PA3nfE9Y1rUgC/kMDR3fQKBgQCyQRRdTICUJV7ATJIlTLmLw1C9sNBzqUuitlXq
            rluS+LZ+HtvXbeFfiKjoH5N07ug/n8GuEZcdJmiTjoMiNH4dOc6ag4vJH+ZB9sZA
            nAnhOJcLNV/V+RSQrvsGbkFWdhGkSEqxaibesTyghFAVwhEcavzIT+Yck55ktwwA
            o0wudQKBgQDR0hyl/cf6MBgZ3gce6dOcznLKoa2icypmmfNkA6sqwXwW20/WfDGb
            ZNdaL4U3xReSN1mzrs0yStq0UrAChwrwqJc6T7uhGR/lDjvJCeZP9zO2yCSBvtul
            LWFkJnofc7NUYkhVSGaAMeT14xUY/XlFbkXp0jZOqKMRo7PeeeXZaQ==
            -----END RSA PRIVATE KEY-----
            """);

    // On Windows, a certificate loaded from PEM-encoded material is ephemeral and
    // cannot be directly used with TLS, as Schannel cannot access it in this case.
    //
    // To work this limitation, the certificate is exported and re-imported from a
    // PFX blob to ensure the private key is persisted in a way that Schannel can use.
    //
    // In a real world application, the certificate wouldn't be embedded in the source code
    // and would be installed in the certificate store, making this workaround unnecessary.
    if (OperatingSystem.IsWindows())
    {
        certificate = X509CertificateLoader.LoadPkcs12(
            data: certificate.Export(X509ContentType.Pfx, string.Empty),
            password: string.Empty,
            keyStorageFlags: X509KeyStorageFlags.DefaultKeySet);
    }

    return new X509SigningCredentials(certificate);
}

#pragma warning disable CS8321
static X509SigningCredentials GetSelfSignedCertificate()
{
    // Note: OpenIddict only negotiates PKI-based or self-signed mutual
    // TLS authentication if the certificate explicitly contains the
    // "digitalSignature" key usage and the "clientAuth" extended key usage.
    var certificate = X509Certificate2.CreateFromPem(
        certPem: $"""
            -----BEGIN CERTIFICATE-----
            MIIC8zCCAdugAwIBAgIJAIZ9BN3TUnZQMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNV
            BAMTF1NlbGYtc2lnbmVkIGNlcnRpZmljYXRlMCAXDTI2MDIwMjE0MzM0OVoYDzIx
            MjYwMjAyMTQzMzQ5WjAiMSAwHgYDVQQDExdTZWxmLXNpZ25lZCBjZXJ0aWZpY2F0
            ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOtfKVPM7ghVFh4U/sz4
            sTrpaNJGQ2NORqawYxAHwluhr101yIOW7rWvFlFncA64Lkq9SAbFFCVSAbo28c6B
            2Mi41jyC4LHQU11jhv08K/3FUuckCuzEpzTnXUhxJHWxrRDVEuvKINGPs1VgVtTT
            ra8rjP8s1YRAzCYnByxSx+8GXNGHprylLh0agpWKb2+2FYwDqY5ME2g3xTL9FTUu
            FYWTcyspsvN0U1Eo1vlCeOxSYGPRct0MK0AS6eXEGBv+3kCYI7a5+UhQok0WvErF
            pjIVo7USISDgKhW9GhTsWN+WywwdG4Kx4V6SB8ZLAHFSBSR3gjWS3TGOyqAWoBXc
            znkCAwEAAaMqMCgwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
            BwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBf5i/S7shmNalVxMuP8/Mk8cOhRRZjnAXd
            zz3eOuXu0CH8iY/DwCgss04O2NTxuz87rKiuNKOrtY0oN/G4aFjWPvbgoQ+N1XP1
            zvbhqbyo3fQr07FyjWkrIUoHYFQ3JRfL+GPGjWizJsgdpdCRJSK6G9VX8eU3Akjv
            YhMRLmbkrH5etOURqFtLpZlxNmLzCpqWIvzRiYyyj74iOipA2I0acgcvkakWn6rE
            Wio7luBAZ3dXlukEfHTOg+ft4k0nOlRXPTtASOmyFQBOs6iYJeztHDz6MQnknAPe
            +W53US8kLWktspcOQmxhVVH1g1/T4ynl9iX7tzqvUbdYwZNi92+x
            -----END CERTIFICATE-----
            """,
        keyPem: $"""
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA618pU8zuCFUWHhT+zPixOulo0kZDY05GprBjEAfCW6GvXTXI
            g5buta8WUWdwDrguSr1IBsUUJVIBujbxzoHYyLjWPILgsdBTXWOG/Twr/cVS5yQK
            7MSnNOddSHEkdbGtENUS68og0Y+zVWBW1NOtryuM/yzVhEDMJicHLFLH7wZc0Yem
            vKUuHRqClYpvb7YVjAOpjkwTaDfFMv0VNS4VhZNzKymy83RTUSjW+UJ47FJgY9Fy
            3QwrQBLp5cQYG/7eQJgjtrn5SFCiTRa8SsWmMhWjtRIhIOAqFb0aFOxY35bLDB0b
            grHhXpIHxksAcVIFJHeCNZLdMY7KoBagFdzOeQIDAQABAoIBAQDgBOqov9uuQo2S
            hBkfrXPBxnXl7MomslG8RRWEJF5wKCtoY9A8rmL0uXhccj7NQ6+LoyvyhZDvFGZg
            ffsXua5DHOmLHmYN12IA+MF6NNMJ7c1CAaQERgd+6tZ2JHm3Kyy1YJdppDAoRMVC
            9Tavyej9WE4ScPGntqSXi33gScnRTEGuuC0HydomT/rmguSWx8oPumeWelSTCh9c
            vZ9Q1NOnRlW/VrNbYyyByiaWEgdrM2E/z3p+MFgrIsYxnIGQ/Ql1FbT0LxbeIYzc
            9MT4cbOlMrD0SZVk9lyxnCs/c1pN7pXDHutmDg6JzSj0xW5AYKzKSvXKjy7+uQay
            YVyYh/QhAoGBAPKL1cZJMqwdQBzHMaHChth5cMh8/IkU6m3U7Ll75dztmaLFce+Y
            Ova6te/D5Cm/l9pxx+vL5fuAafc2/FTesmKkE2DEERvy4EOQqB1Uho6XEoBBfnJT
            0xmNY5Jvh0TfyquS23KvzezT7+epFYNhZDQwgWPnx2z+jwa/zn8Ows/nAoGBAPht
            crkmXBMncO7CXzFzFbDghIitW9cZnqBTzKwr2k9lVsbioTIYDbGruvABwI5sN2b4
            gJqcvnkun7dmooRPAGX/nMl5UxeGhdSlYGVzHchZz/310MdEg/JThIV219sHR5fd
            pBlrydWDyfDTkiGZHDiYUzuZ6hCyOjf+MUgGlyKfAoGBAKYblF1G9hgftC/BT8Fb
            quQIT3BPANiU5XQwtarWKndilax/EmenVwJwnndFLjZVS5dEA0n+i1Px/yBanPc2
            yO57NfY4cQs2C9bZ8/iaUcjHt9j0gbekptdCGKZKEVbe+TsFyZrCwgHmp8984gnn
            IiwH6CVWsCJ6N9PEepRTtKGTAoGAV/wTdKW0WIhQhA9NPas/1GxAJFQZwd3uA2SK
            ibPiVtpSWJAtfRttxi5HP/eu5gJHwO1kRt4ay7qKkJ8GEgwU3Qsh0W1p01wui/ii
            YmvZ8Xp1osFr1xdaD/oqZkaH/qfeYFf8ZZB6ZGePnv6fs8yRZS311JcXgiBNZEVf
            2N2Uq4sCgYAoVe3zkP37MjIH6nykFiR396den5ZyMflR42QtO0Z2QJuQKs6yZ7ii
            cqQy4r1Z2i6bdtUlesyGF5U7BPvcers/Mczax0u81Y2S9PdIsv8cw8sr8M6HHiS3
            IWBJpVJNyoHKLusRTYVqti+b5EHXQ55FZ9EJggvceGbcBamZ+ynYrg==
            -----END RSA PRIVATE KEY-----
            """);

    // On Windows, a certificate loaded from PEM-encoded material is ephemeral and
    // cannot be directly used with TLS, as Schannel cannot access it in this case.
    //
    // To work this limitation, the certificate is exported and re-imported from a
    // PFX blob to ensure the private key is persisted in a way that Schannel can use.
    //
    // In a real world application, the certificate wouldn't be embedded in the source code
    // and would be installed in the certificate store, making this workaround unnecessary.
    if (OperatingSystem.IsWindows())
    {
        certificate = X509CertificateLoader.LoadPkcs12(
            data: certificate.Export(X509ContentType.Pfx, string.Empty),
            password: string.Empty,
            keyStorageFlags: X509KeyStorageFlags.DefaultKeySet);
    }

    return new X509SigningCredentials(certificate);
}

static SigningCredentials GetSigningKey()
{
    var algorithm = ECDsa.Create();
    algorithm.ImportFromPem($"""
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIMGxf/eMzKuW2F8KKWPJo3bwlrO68rK5+xCeO1atwja2oAoGCCqGSM49
        AwEHoUQDQgAEI23kaVsRRAWIez/pqEZOByJFmlXda6iSQ4QqcH23Ir8aYPPX5lsV
        nBsExNsl7SOYOiIhgTaX6+PTS7yxTnmvSw==
        -----END EC PRIVATE KEY-----
        """);

    var key = new ECDsaSecurityKey(algorithm);

    return new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.Sha256);
}
#pragma warning restore CS8321
