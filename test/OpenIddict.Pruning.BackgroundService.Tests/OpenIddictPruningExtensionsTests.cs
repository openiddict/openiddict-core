using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Pruning.BackgroundService.Tests;

public class OpenIddictPruningExtensionsTests
{
   //The background service implementation changed between .NET framework and .NET Core
#if NET
   private const ServiceLifetime ExpectedLifetime = ServiceLifetime.Singleton;
#else
   private const ServiceLifetime ExpectedLifetime = ServiceLifetime.Transient;
#endif
    [Fact]
    public void UsePruning_ThrowsAnExceptionForNullBuilder()
    {
        // Arrange
        var builder = (OpenIddictCoreBuilder) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(builder.UseBackgroundServicePruning);

        Assert.Equal("builder", exception.ParamName);
    }

    [Fact]
    public void UsePruning_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.UseBackgroundServicePruning(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void UsePruning_RegistersJobService()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseBackgroundServicePruning();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IHostedService) &&
            service.ImplementationType == typeof(OpenIddictPruningBackgroundService) &&
            service.Lifetime == ExpectedLifetime);
    }

    [Fact]
    public void UsePruning_CanBeSafelyInvokedMultipleTimes()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictCoreBuilder(services);

        // Act
        builder.UseBackgroundServicePruning();
        builder.UseBackgroundServicePruning();
        builder.UseBackgroundServicePruning();

        // Assert
        Assert.Single(services, service => service.ServiceType == typeof(IHostedService) &&
            service.ImplementationType == typeof(OpenIddictPruningBackgroundService) &&
            service.Lifetime == ExpectedLifetime);

        Assert.Single(services, service => service.ServiceType == typeof(IConfigureOptions<OpenIddictPruningOptions>) &&
            service.ImplementationType == typeof(OpenIddictPruningConfiguration) &&
            service.Lifetime == ServiceLifetime.Singleton);
    }
}
