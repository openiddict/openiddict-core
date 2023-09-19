using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.EntityFrameworkCore.Factory;

internal class OpeniddictEntityFrameworkCoreContextFactory : IOpeniddictEntityFrameworkCoreContextFactory
{
    protected IServiceProvider ServiceProvider { get; }

    public OpeniddictEntityFrameworkCoreContextFactory(IServiceProvider serviceProvider)
    {
        ServiceProvider = serviceProvider;
    }

    public DbContext CreateDbContext()
    {
        var options = ServiceProvider.GetService<IOptions<OpenIddictEntityFrameworkCoreOptions>>().Value;
        if (options.DbContextFactoryType == null)
        {
            return options.GetDbContext(ServiceProvider);
        }
        else
        {
            return ServiceProvider.GetService(options.DbContextFactoryType) is IOpeniddictEntityFrameworkCoreContextFactory factory ?
                factory.CreateDbContext() :
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0252));
        }
    }
}
