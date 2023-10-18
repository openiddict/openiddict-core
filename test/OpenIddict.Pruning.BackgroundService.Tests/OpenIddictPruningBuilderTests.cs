using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Pruning.BackgroundService.Tests;

public class OpenIddictPruningBuilderTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForNullServices()
    {
        // Arrange
        var services = (IServiceCollection) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictPruningBuilder(services));

        Assert.Equal("services", exception.ParamName);
    }

    [Fact]
    public void Configure_DelegateIsCorrectlyRegistered()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);
        var configuration = new Action<OpenIddictPruningOptions>(options => { });

        // Act
        builder.Configure(configuration);

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IConfigureOptions<OpenIddictPruningOptions>) &&
            service.ImplementationInstance is ConfigureNamedOptions<OpenIddictPruningOptions> options &&
            options.Action == configuration && string.IsNullOrEmpty(options.Name));
    }

    [Fact]
    public void Configure_ThrowsAnExceptionWhenConfigurationIsNull()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.Configure(configuration: null!));
        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void DisableAuthorizationPruning_AuthorizationPruningIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableAuthorizationPruning();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableAuthorizationPruning);
    }

    [Fact]
    public void DisableTokenPruning_TokenPruningIsDisabled()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.DisableTokenPruning();

        var options = GetOptions(services);

        // Assert
        Assert.True(options.DisableTokenPruning);
    }

    [Fact]
    public void SetFirstRun_FirstRunIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetFirstRun(TimeSpan.Zero);

        var options = GetOptions(services);

        // Assert
        Assert.Equal(TimeSpan.Zero, options.FirstRun);
    }
    [Fact]
    public void SetInterval_IntervalIsSet()
    {
       // Arrange
       var services = CreateServices();
       var builder = CreateBuilder(services);

       // Act
       builder.SetInterval(TimeSpan.Zero);

       var options = GetOptions(services);

       // Assert
       Assert.Equal(TimeSpan.Zero, options.Interval);
    }

    [Fact]
    public void SetMinimumAuthorizationLifespan_ThrowsAnExceptionForNegativeLifespan()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetMinimumAuthorizationLifespan(TimeSpan.FromSeconds(-1)));

        Assert.Equal("lifespan", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0280), exception.Message);
    }

    [Fact]
    public void SetMinimumAuthorizationLifespan_MinimumAuthorizationLifespanIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMinimumAuthorizationLifespan(TimeSpan.FromDays(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(42, options.MinimumAuthorizationLifespan.TotalDays);
    }

    [Fact]
    public void SetMinimumTokenLifespan_ThrowsAnExceptionForNegativeLifespan()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetMinimumTokenLifespan(TimeSpan.FromSeconds(-1)));

        Assert.Equal("lifespan", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0280), exception.Message);
    }

    [Fact]
    public void SetMinimumTokenLifespan_MinimumTokenLifespanIsSet()
    {
        // Arrange
        var services = CreateServices();
        var builder = CreateBuilder(services);

        // Act
        builder.SetMinimumTokenLifespan(TimeSpan.FromDays(42));

        var options = GetOptions(services);

        // Assert
        Assert.Equal(42, options.MinimumTokenLifespan.TotalDays);
    }

    private static IServiceCollection CreateServices()
        => new ServiceCollection().AddOptions();

    private static OpenIddictPruningBuilder CreateBuilder(IServiceCollection services)
        => new OpenIddictPruningBuilder(services);

    private static OpenIddictPruningOptions GetOptions(IServiceCollection services)
    {
        var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>();
        return options.Value;
    }
}
