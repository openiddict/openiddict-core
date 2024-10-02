using System;
using System.Configuration;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Autofac.Integration.Mvc;
using Autofac.Integration.WebApi;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Abstractions;
using OpenIddict.Client.Owin;
using OpenIddict.Sandbox.AspNet.Server.Models;
using OpenIddict.Server.Owin;
using OpenIddict.Validation.Owin;
using Owin;
using static System.Net.WebRequestMethods;
using static OpenIddict.Abstractions.OpenIddictConstants;

[assembly: OwinStartup(typeof(OpenIddict.Sandbox.AspNet.Server.Startup))]
namespace OpenIddict.Sandbox.AspNet.Server;

public class Startup
{
    public void Configuration(IAppBuilder app)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework 6.x stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFramework()
                       .UseDbContext<ApplicationDbContext>();

                // Developers who prefer using MongoDB can remove the previous lines
                // and configure OpenIddict to use the specified MongoDB database:
                // options.UseMongoDb()
                //        .UseDatabase(new MongoClient().GetDatabase("openiddict"));
            })

            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Note: this sample uses the code flow, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow();

                var privateKeyXml = "<RSAKeyValue><Modulus>uSQBwbidg8/lAw3N3xeWmc9uYQPMHH5fODGmER6uXRzzJaL8upFWXanwts7ILNFOFAWogxQuWaTqu4dUFDVuXhJsdxpT4YZy0+k8QEMyBi6VIenQtKhYgiCgx9RK6cAuXRN1X6iQ2F+3MaenUGxztEOSQ1iJarV7E5od0o0doDl0TcW/wVqnwpAc5j8K/06kICuy1Pb1glHZsF8vzCgTPwdBTAYLGbzJWWxpLNiEFDuvJR6lopSSxKpurvzYXgpZHMZuOUlmQM/XGXjCYctHldAmr+gp8/xtufx3w2/V3gApLS6kWdkA9xazLOt7Xqb2QBGNGbunVzhtGg2rBYdBXQ==</Modulus><Exponent>AQAB</Exponent><P>wiiY1qCfHaiO+FoVpB3OocUYtqI9WvXUV2tk/JIOVuBth5oRg01GMN1cMA085YcwlV1d2RQVqGXdhAKHUwyi73luFQ/yt5ehemPUQPau03Pv8GkySLSGsbwuK+FKpDQ9kdupG1eW6dBt91um4Q1Gtu+GAJ2LkucYRHA2yx6osIs=</P><Q>9BwZ5gtnMw70n/h8NvULco5RxxpfoQ++2D7iQ6rc7i27/k53E0is2L03PP/LR8bV/14z+ixMW6rH7G2d475NIzFTrR4HjZdf+i05Fq7N/xvNCLrUvAd0CWqxYrume0t9zfw62JQtp5IYQ3g9K7DxUwfY9qVwYlZByLkgrUz26rc=</Q><DP>m2n5pVte4lOpVXxudDbzzqPA+3f0WtoKBYvOgym6VqpAolmeCRcSx0x5XXFLPIMxTW42D+w2xdv8K44GmmC0D7KIfk2MwI6cUCaWoQWUvWfBORRLjs0KQDzcTH2CzNuQKS/GNj+vaitPyr9PXjfNUeN6xQVW0tkuoKGeCorZBq8=</DP><DQ>HOd26ZZQEeuja42wp5E8WcQgSsMEr719i31mrTx+DHW93M7NqqrgTImbEM348/bHQAWXgffc0r3WDlisaVsPJyugDM+RdWKHKshQCi+IlLxl+rKknd8EDlljx50QiWjW7J0BGsPw4/aYiOSj2ZiJ+prjRdExDXPJNks1Y0/JrOE=</DQ><InverseQ>g+JNJBZbKFIY5jWZxCeX7TW25KpR498x+0yGJlzCwy23JbBGDupt2tsBnhXr8KuTxSfMOGWtazQeipI//XyLCvV7BohkL6PhzMKKHwAoM/0xNaqA0d5t9Q32OqEn6I+deu4SF4OwMXkQ96xGp0zLlsWnw3HdG2rVtx5KYARMmGA=</InverseQ><D>YA+CqdT0RXQUyyTacKp4hY3PI58oxI/9L9by52cX6VAgCKMsplDKkwad0vwveLGQ5WqaKIjME88xy+NHiMTAYycECDgs1ZNA+RrHHEDBL9vznQkINPQ0GDB9u7E2vVnttHVoLR31KY9gKe9nLJ9Y2WtF9JN3mVpYZa9NUfXOLVc+zs6ChwqfryfrkgQGHZXNFtwYhG4KuOLkrQy2S4etJEWn+NMbJVYEmy1Sg99BZs4eyi0666B30ofUsx6GwyCa9IXgDm4cJnUDQu0ZEGNU7LX+p9lFym13DkWt4z9TuE3QeOSr7jHEQz1CdE8a4zsqdf3TKP2Fl05+URL35kr/MQ==</D></RSAKeyValue>";
                var rsa = RSA.Create(2048);
                rsa.FromXmlString(privateKeyXml);

                options.AddEncryptionKey(new SymmetricSecurityKey(Convert.FromBase64String("DRjd/GnduI3Efzen9V9BvbNUfc/VKgXltV7Kbk9sMkY=")));
                options.AddSigningKey(new RsaSecurityKey(rsa));

                // Register the OWIN host and configure the OWIN-specific options.
                options.UseOwin()
                       .EnableRedirectionEndpointPassthrough()
                       .SetCookieManager(new SystemWebCookieManager());

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

                // Note: this sample uses the code, device code, password and refresh token flows, but you
                // can enable the other flows if you need to support implicit or client credentials.
                options.AllowAuthorizationCodeFlow()
                       .AllowDeviceCodeFlow()
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

                // Register the OWIN host and configure the OWIN-specific options.
                options.UseOwin()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableTokenEndpointPassthrough();

            })

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Register the OWIN host.
                options.UseOwin();
            });

        // Create a new Autofac container and import the OpenIddict services.
        var builder = new ContainerBuilder();
        builder.Populate(services);

        // Register the MVC controllers.
        builder.RegisterControllers(typeof(Startup).Assembly);

        // Register the Web API controllers.
        builder.RegisterApiControllers(typeof(Startup).Assembly);

        var container = builder.Build();

        // Register the Autofac scope injector middleware.
        app.UseAutofacLifetimeScopeInjector(container);

        // Register the Entity Framework context and the user/sign-in managers used by ASP.NET Identity.
        app.CreatePerOwinContext(ApplicationDbContext.Create);
        app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
        app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

        // Register the cookie middleware used by ASP.NET Identity.
        app.UseCookieAuthentication(new CookieAuthenticationOptions
        {
            AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
            LoginPath = new PathString("/Account/Login"),
            Provider = new CookieAuthenticationProvider
            {
                OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                    validateInterval: TimeSpan.FromMinutes(30),
                    regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
            }
        });

        app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
        app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));
        app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

        // Register the OpenIddict middleware.
        app.UseMiddlewareFromContainer<OpenIddictClientOwinMiddleware>();
        app.UseMiddlewareFromContainer<OpenIddictServerOwinMiddleware>();
        app.UseMiddlewareFromContainer<OpenIddictValidationOwinMiddleware>();

        // Configure ASP.NET MVC 5.2 to use Autofac when activating controller instances.
        DependencyResolver.SetResolver(new AutofacDependencyResolver(container));

        // Configure ASP.NET MVC 5.2 to use Autofac when activating controller instances
        // and infer the Web API routes using the HTTP attributes used in the controllers.
        var configuration = new HttpConfiguration
        {
            DependencyResolver = new AutofacWebApiDependencyResolver(container)
        };

        configuration.MapHttpAttributeRoutes();
        configuration.SuppressDefaultHostAuthentication();

        // Register the Autofac Web API integration and Web API middleware.
        app.UseAutofacWebApi(configuration);
        app.UseWebApi(configuration);

        // Seed the database with the sample client using the OpenIddict application manager.
        // Note: in a real world application, this step should be part of a setup script.
        Task.Run(async delegate
        {
            await using var scope = container.BeginLifetimeScope();

            var context = scope.Resolve<ApplicationDbContext>();
            context.Database.CreateIfNotExists();

            var manager = scope.Resolve<IOpenIddictApplicationManager>();

            if (await manager.FindByClientIdAsync("mvc") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Web,
                    ClientId = "mvc",
                    ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                    ClientType = ClientTypes.Confidential,
                    ConsentType = ConsentTypes.Explicit,
                    DisplayName = "MVC client application",
                    RedirectUris =
                    {
                        new Uri("https://localhost:44378/callback/login/local")
                    },
                    PostLogoutRedirectUris =
                    {
                        new Uri("https://localhost:44378/callback/logout/local")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "demo_api"
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    }
                });
            }

            if (await manager.FindByClientIdAsync("postman") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
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
                        Permissions.Endpoints.Device,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.DeviceCode,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Settings =
                    {
                        // Use a shorter access token lifetime for tokens issued to the Postman application.
                        [Settings.TokenLifetimes.AccessToken] = TimeSpan.FromMinutes(10).ToString("c", CultureInfo.InvariantCulture)
                    }
                });
            }

            if (await manager.FindByClientIdAsync("maui") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
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
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "demo_api"
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    }
                });
            }

            if (await manager.FindByClientIdAsync("avalonia") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "avalonia",
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "Avalonia client application",
                    DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente avalonia"
                    },
                    PostLogoutRedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.avalonia.client:/callback/logout/local")
                    },
                    RedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.avalonia.client:/callback/login/local")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "demo_api"
                    },
                    Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    }
                });
            }
        }).GetAwaiter().GetResult();
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