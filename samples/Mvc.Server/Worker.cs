using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Mvc.Server.Models;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Mvc.Server
{
    public class Worker : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public Worker(IServiceProvider serviceProvider)
            => _serviceProvider = serviceProvider;

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using var scope = _serviceProvider.CreateScope();

            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync();

            await RegisterApplicationsAsync(scope.ServiceProvider);
            await RegisterScopesAsync(scope.ServiceProvider);

            static async Task RegisterApplicationsAsync(IServiceProvider provider)
            {
                var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

                if (await manager.FindByClientIdAsync("mvc") == null)
                {
                    await manager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "mvc",
                        ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                        ConsentType = ConsentTypes.Explicit,
                        DisplayName = "MVC client application",
                        PostLogoutRedirectUris =
                        {
                            new Uri("http://localhost:53507/signout-callback-oidc")
                        },
                        RedirectUris =
                        {
                            new Uri("http://localhost:53507/signin-oidc")
                        },
                        Permissions =
                        {
                            Permissions.Endpoints.Authorization,
                            Permissions.Endpoints.Logout,
                            Permissions.Endpoints.Token,
                            Permissions.GrantTypes.AuthorizationCode,
                            Permissions.GrantTypes.RefreshToken,
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

                // To test this sample with Postman, use the following settings:
                //
                // * Authorization URL: http://localhost:54540/connect/authorize
                // * Access token URL: http://localhost:54540/connect/token
                // * Client ID: postman
                // * Client secret: [blank] (not used with public clients)
                // * Scope: openid email profile roles
                // * Grant type: authorization code
                // * Request access token locally: yes
                if (await manager.FindByClientIdAsync("postman") == null)
                {
                    await manager.CreateAsync(new OpenIddictApplicationDescriptor
                    {
                        ClientId = "postman",
                        ConsentType = ConsentTypes.Systematic,
                        DisplayName = "Postman",
                        RedirectUris =
                        {
                            new Uri("urn:postman")
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
                            Permissions.Scopes.Email,
                            Permissions.Scopes.Profile,
                            Permissions.Scopes.Roles
                        }
                    });
                }
            }

            static async Task RegisterScopesAsync(IServiceProvider provider)
            {
                var manager = provider.GetRequiredService<IOpenIddictScopeManager>();

                if (await manager.FindByNameAsync("demo_api") == null)
                {
                    await manager.CreateAsync(new OpenIddictScopeDescriptor
                    {
                        DisplayName = "Demo API access",
                        Name = "demo_api",
                        Resources =
                        {
                            "resource_server"
                        }
                    });
                }
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
