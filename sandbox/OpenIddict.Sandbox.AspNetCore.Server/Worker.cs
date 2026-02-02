using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Sandbox.AspNetCore.Server.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.Server;

public class Worker : IHostedService
{
    private readonly IServiceProvider _provider;

    public Worker(IServiceProvider provider)
        => _provider = provider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _provider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        await RegisterApplicationsAsync(scope.ServiceProvider);
        await RegisterScopesAsync(scope.ServiceProvider);

        static async Task RegisterApplicationsAsync(IServiceProvider provider)
        {
            var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("console") is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    // Note: the application must be registered as a native application to force OpenIddict
                    // to apply a relaxed redirect_uri validation policy that allows specifying a random port.
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "console",
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "Console client application",
                    DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente console"
                    },
                    PostLogoutRedirectUris =
                    {
                        // Note: the port must not be explicitly specified as it is selected
                        // dynamically at runtime by the OpenIddict client system integration.
                        new Uri("http://localhost/callback/logout/local")
                    },
                    RedirectUris =
                    {
                        // Note: the port must not be explicitly specified as it is selected
                        // dynamically at runtime by the OpenIddict client system integration.
                        new Uri("http://localhost/callback/login/local")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.DeviceAuthorization,
                        Permissions.Endpoints.Introspection,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.PushedAuthorization,
                        Permissions.Endpoints.Revocation,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.DeviceCode,
                        Permissions.GrantTypes.Implicit,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.GrantTypes.TokenExchange,
                        Permissions.ResponseTypes.Code,
                        Permissions.ResponseTypes.CodeIdToken,
                        Permissions.ResponseTypes.CodeIdTokenToken,
                        Permissions.ResponseTypes.CodeToken,
                        Permissions.ResponseTypes.IdToken,
                        Permissions.ResponseTypes.IdTokenToken,
                        Permissions.ResponseTypes.None,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange,
                        Requirements.Features.PushedAuthorizationRequests
                    }
                };

                descriptor.AddScopePermissions("demo_api");

                await manager.CreateAsync(descriptor);
            }

            if (await manager.FindByClientIdAsync("maui") is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "maui",
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "MAUI client application",
                    DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente MAUI"
                    },
                    PostLogoutRedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.maui.client:/callback/logout/local")
                    },
                    RedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.maui.client:/callback/login/local")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.PushedAuthorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange,
                        Requirements.Features.PushedAuthorizationRequests
                    }
                };

                descriptor.AddScopePermissions("demo_api");

                await manager.CreateAsync(descriptor);
            }

            if (await manager.FindByClientIdAsync("mvc") is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Web,
                    ClientId = "mvc",
                    ClientType = ClientTypes.Confidential,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "MVC client application",
                    DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente MVC"
                    },
#if SUPPORTS_PEM_ENCODED_KEY_IMPORT
                    JsonWebKeySet = new JsonWebKeySet
                    {
                        Keys =
                        {
                            // On supported platforms, this application can authenticate by using a
                            // self-signed client authentication certificate during the TLS handshake
                            // (a method known as "mutual TLS" or mTLS).
                            //
                            // Note: while the client needs access to the private key, the server only needs
                            // to know the public part to be able to validate the certificates it receives.
                            JsonWebKeyConverter.ConvertFromX509SecurityKey(new X509SecurityKey(
                                X509Certificate2.CreateFromPem($"""
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
                                    """))),

                            // On supported platforms, this application can also authenticate by
                            // generating JWT client assertions that are signed using a signing key.
                            //
                            // Note: while the client needs access to the private key, the server only needs
                            // to know the public key to be able to validate the client assertions it receives.
                            JsonWebKeyConverter.ConvertFromECDsaSecurityKey(GetECDsaSigningKey($"""
                                -----BEGIN PUBLIC KEY-----
                                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEI23kaVsRRAWIez/pqEZOByJFmlXd
                                a6iSQ4QqcH23Ir8aYPPX5lsVnBsExNsl7SOYOiIhgTaX6+PTS7yxTnmvSw==
                                -----END PUBLIC KEY-----
                                """))
                        }
                    },
#else
                    ClientSecret = "emCimpdc9SeOaZzN5jzm4_eek-STF6VenfVlKO1_qt0",
#endif
                    RedirectUris =
                    {
                        new Uri("https://localhost:44381/callback/login/local")
                    },
                    PostLogoutRedirectUris =
                    {
                        new Uri("https://localhost:44381/callback/logout/local")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.PushedAuthorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange,
                        Requirements.Features.PushedAuthorizationRequests
                    }
                };

                descriptor.AddScopePermissions("demo_api");

                await manager.CreateAsync(descriptor);
            }

            if (await manager.FindByClientIdAsync("winforms") is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "winforms",
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "WinForms client application",
                    DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente WinForms"
                    },
                    PostLogoutRedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.winforms.client:/callback/logout/local")
                    },
                    RedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.winforms.client:/callback/login/local")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.PushedAuthorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange,
                        Requirements.Features.PushedAuthorizationRequests
                    }
                };

                descriptor.AddScopePermissions("demo_api");

                await manager.CreateAsync(descriptor);
            }

            if (await manager.FindByClientIdAsync("wpf") is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "wpf",
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "WPF client application",
                    DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente WPF"
                    },
                    PostLogoutRedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.wpf.client:/callback/logout/local")
                    },
                    RedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.wpf.client:/callback/login/local")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.EndSession,
                        Permissions.Endpoints.PushedAuthorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange,
                        Requirements.Features.PushedAuthorizationRequests
                    }
                };

                descriptor.AddScopePermissions("demo_api");

                await manager.CreateAsync(descriptor);
            }

            // Note: when using introspection instead of local token validation,
            // an application entry MUST be created to allow the resource server
            // to communicate with OpenIddict's introspection endpoint.
            if (await manager.FindByClientIdAsync("resource_server") is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ClientId = "resource_server",
                    ClientSecret = "vVQ-yjr42sXP5VHj6AswkXuS7MU1i2gFjvJjY0TdGMk",
                    ClientType = ClientTypes.Confidential,
                    Permissions =
                    {
                        Permissions.Endpoints.Introspection
                    }
                };

                await manager.CreateAsync(descriptor);
            }

            // To test this sample with Postman, use the following settings:
            //
            // * Authorization URL: https://localhost:44395/connect/authorize
            // * Access token URL: https://localhost:44395/connect/token
            // * Client ID: postman
            // * Client secret: [blank] (not used with public clients)
            // * Scope: openid email profile roles
            // * Grant type: authorization code
            // * Request access token locally: yes
            if (await manager.FindByClientIdAsync("postman") is null)
            {
                var descriptor = new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "postman",
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "Postman",
                    RedirectUris =
                    {
                        new Uri("https://oauth.pstmn.io/v1/callback")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.DeviceAuthorization,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.DeviceCode,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    }
                };

                // Use a shorter access token lifetime for tokens issued to the Postman application.
                descriptor.SetAccessTokenLifetime(TimeSpan.FromMinutes(10));

                await manager.CreateAsync(descriptor);
            }

#if SUPPORTS_PEM_ENCODED_KEY_IMPORT
            static ECDsaSecurityKey GetECDsaSigningKey(ReadOnlySpan<char> key)
            {
                var algorithm = ECDsa.Create();
                algorithm.ImportFromPem(key);

                return new ECDsaSecurityKey(algorithm);
            }
#endif
        }

        static async Task RegisterScopesAsync(IServiceProvider provider)
        {
            var manager = provider.GetRequiredService<IOpenIddictScopeManager>();

            if (await manager.FindByNameAsync("demo_api") is null)
            {
                var descriptor = new OpenIddictScopeDescriptor
                {
                    DisplayName = "Demo API access",
                    DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Accès à l'API de démo"
                    },
                    Name = "demo_api",
                    Resources =
                    {
                        "resource_server"
                    }
                };

                await manager.CreateAsync(descriptor);
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
