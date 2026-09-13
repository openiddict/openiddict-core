using Company.Server.Data;
using OpenIddict.Abstractions;

namespace Company.Server;

/// <summary>
/// Creates the database and registers the client applications declared in the "OpenIddict:Clients" section.
/// </summary>
/// <remarks>In production, the database should be created using migrations as part of the deployment.</remarks>
public class Worker(IServiceProvider provider, IConfiguration configuration) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = provider.CreateAsyncScope();

        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await context.Database.EnsureCreatedAsync(cancellationToken);

        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        foreach (var client in configuration.GetSection("OpenIddict:Clients").Get<List<ClientDefinition>>() ?? [])
        {
            if (string.IsNullOrEmpty(client.ClientId) ||
                await manager.FindByClientIdAsync(client.ClientId, cancellationToken) is not null)
            {
                continue;
            }

            await manager.CreateAsync(client.CreateDescriptor(), cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
