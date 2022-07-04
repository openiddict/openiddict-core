using Microsoft.EntityFrameworkCore;

namespace OpenIddict.Sandbox.Maui.Client;

public class Worker : IMauiInitializeScopedService
{
    private readonly IServiceProvider _serviceProvider;

    public Worker(IServiceProvider serviceProvider)
        => _serviceProvider = serviceProvider;

    public void Initialize(IServiceProvider services)
    {
        using var scope = _serviceProvider.CreateScope();

        var context = scope.ServiceProvider.GetRequiredService<DbContext>();
        context.Database.EnsureCreated();
    }
}
