/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictCoreExtensionsTests
{
    [Fact]
    public void AddCore_ThrowsAnExceptionForNullBuilder()
    {
        // Arrange
        var builder = (OpenIddictBuilder) null!;

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(builder.AddCore);

        Assert.Equal("builder", exception.ParamName);
    }

    [Fact]
    public void AddCore_ThrowsAnExceptionForNullConfiguration()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => builder.AddCore(configuration: null!));

        Assert.Equal("configuration", exception.ParamName);
    }

    [Fact]
    public void AddCore_RegistersLoggingServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(ILogger<>));
    }

    [Fact]
    public void AddCore_RegistersOptionsServices()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == typeof(IOptions<>));
    }

    [Theory]
    [InlineData(typeof(OpenIddictApplicationManager<>))]
    [InlineData(typeof(OpenIddictAuthorizationManager<>))]
    [InlineData(typeof(OpenIddictScopeManager<>))]
    [InlineData(typeof(OpenIddictTokenManager<>))]
    public void AddCore_RegistersDefaultManagers(Type type)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == type && service.ImplementationType == type);
    }

    [Theory]
    [InlineData(typeof(IOpenIddictApplicationManager))]
    [InlineData(typeof(IOpenIddictAuthorizationManager))]
    [InlineData(typeof(IOpenIddictScopeManager))]
    [InlineData(typeof(IOpenIddictTokenManager))]
    public void AddCore_RegistersUntypedProxies(Type type)
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        Assert.Contains(services, service => service.ServiceType == type && service.ImplementationFactory is not null);
    }

    [Fact]
    public void AddCore_ResolvingUntypedApplicationManagerThrowsAnException()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(provider.GetRequiredService<IOpenIddictApplicationManager>);

        Assert.Equal(SR.GetResourceString(SR.ID0472), exception.Message);
    }

    [Fact]
    public void AddCore_ResolvingUntypedAuthorizationManagerThrowsAnException()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(provider.GetRequiredService<IOpenIddictAuthorizationManager>);

        Assert.Equal(SR.GetResourceString(SR.ID0472), exception.Message);
    }

    [Fact]
    public void AddCore_ResolvingUntypedScopeManagerThrowsAnException()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(provider.GetRequiredService<IOpenIddictScopeManager>);

        Assert.Equal(SR.GetResourceString(SR.ID0472), exception.Message);
    }

    [Fact]
    public void AddCore_ResolvingUntypedTokenManagerThrowsAnException()
    {
        // Arrange
        var services = new ServiceCollection();
        var builder = new OpenIddictBuilder(services);

        // Act
        builder.AddCore();

        // Assert
        var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(provider.GetRequiredService<IOpenIddictTokenManager>);

        Assert.Equal(SR.GetResourceString(SR.ID0472), exception.Message);
    }

    public class OpenIddictApplication { }
    public class OpenIddictAuthorization { }
    public class OpenIddictScope { }
    public class OpenIddictToken { }
}
