using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Sandbox.AspNetCore.CimdServer.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNetCore.CimdServer;

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

        await SeedUsersAsync(scope.ServiceProvider);
        await SeedClientsAsync(scope.ServiceProvider);
    }

    private static async Task SeedUsersAsync(IServiceProvider provider)
    {
        var userManager = provider.GetRequiredService<UserManager<ApplicationUser>>();

        if (await userManager.FindByNameAsync("testuser") is null)
        {
            var user = new ApplicationUser
            {
                UserName = "testuser",
                Email = "testuser@example.com"
            };

            await userManager.CreateAsync(user, "Pass123$");
        }
    }

    private static async Task SeedClientsAsync(IServiceProvider provider)
    {
        var manager = provider.GetRequiredService<IOpenIddictApplicationManager>();

        // Pre-registered test client for baseline verification.
        if (await manager.FindByClientIdAsync("test-client") is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ApplicationType = ApplicationTypes.Native,
                ClientId = "test-client",
                ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Systematic,
                DisplayName = "Test client (pre-registered)",
                RedirectUris =
                {
                    new Uri("http://localhost/callback")
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.Password,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            });
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
