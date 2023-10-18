using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Pruning.BackgroundService.Tests;

public class OpenIddictPruningJobTests
{
    [Fact]
    public async Task Execute_UsesServiceScope()
    {
        // Arrange
        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == provider);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictPruningOptions>>(
            monitor => monitor.CurrentValue == new OpenIddictPruningOptions());
        var logger = Mock.Of<ILogger<OpenIddictPruningBackgroundService>>();

        var job = new OpenIddictPruningBackgroundService(monitor,
            Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory), logger);

        // Act
        await job.PruneAsync(CancellationToken.None);

        Mock.Get(factory).Verify(factory => factory.CreateScope(), Times.Once());
        Mock.Get(scope).Verify(scope => scope.Dispose(), Times.Once());
    }

    [Fact]
    public async Task Execute_IgnoresPruningWhenTokenPruningIsDisabled()
    {
        // Arrange

        var manager = new Mock<IOpenIddictAuthorizationManager>();

        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);

        var job = CreateJob(provider, new OpenIddictPruningOptions
        {
            DisableTokenPruning = true,
        });

        // Act
        await job.PruneAsync(CancellationToken.None);

        // Assert
        manager.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task Execute_IgnoresPruningWhenAuthorizationPruningIsDisabled()
    {
        // Arrange

        var manager = new Mock<IOpenIddictAuthorizationManager>();

        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

        var job = CreateJob(provider, new OpenIddictPruningOptions
        {
            DisableAuthorizationPruning = true,
        });

        // Act
        await job.PruneAsync(CancellationToken.None);

        // Assert
        manager.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task Execute_UnschedulesTriggersWhenTokenManagerIsMissing()
    {
        // Arrange
        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == null);

        var job = CreateJob(provider);

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => job.PruneAsync(CancellationToken.None));

        Assert.Equal(SR.GetResourceString(SR.ID0278), exception.Message);
    }

    [Fact]
    public async Task Execute_UnschedulesTriggersWhenAuthorizationManagerIsMissing()
    {
        // Arrange
        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == null);

        var job = CreateJob(provider);

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => job.PruneAsync(CancellationToken.None));

        Assert.Equal(SR.GetResourceString(SR.ID0278), exception.Message);
    }

    [Fact]
    public async Task Execute_RethrowsArgumentExceptionsThrownDuringTokenPruning()
    {
        // Arrange
        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(new ArgumentException());

        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);

        var job = CreateJob(provider);

        // Act and assert
        var exception = await Assert.ThrowsAsync<AggregateException>(() => job.PruneAsync(CancellationToken.None));
        Assert.IsType<ArgumentException>(exception.InnerException);
    }

    [Fact]
    public async Task Execute_RethrowsArgumentExceptionsThrownDuringAuthorizationPruning()
    {
        // Arrange
        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(new ArgumentException());

        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

        var job = CreateJob(provider);

        // Act and assert
        var exception = await Assert.ThrowsAsync<AggregateException>(() => job.PruneAsync(CancellationToken.None));
        Assert.IsType<ArgumentException>(exception.InnerException);
    }

    [Fact]
    public async Task Execute_ReturnWhenJobIsCanceledDuringTokenPruning()
    {
        // Arrange
        var token = new CancellationToken(canceled: true);

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(new OperationCanceledException(token));
        var manager2 = new Mock<IOpenIddictAuthorizationManager>();
        manager2.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
           .Throws(new ArgumentException());

        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager2.Object &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);

        var job = CreateJob(provider);

        // Act and assert
        await job.PruneAsync(token);

        manager.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        manager2.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task Execute_IgnoreErrorsFromTokenManagerWhenJobIsCanceledDuringAuthorizationPruning()
    {
        // Arrange
        var token = new CancellationToken(canceled: true);

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(new OperationCanceledException(token));
        var manager2 = new Mock<IOpenIddictTokenManager>();
        manager2.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
           .Throws(new ArgumentException());
        var provider = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object &&
            provider.GetService(typeof(IOpenIddictTokenManager)) == manager2.Object);

        var job = CreateJob(provider);

        // Act and assert
        await job.PruneAsync(token);

        manager.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }
   
    private static OpenIddictPruningBackgroundService CreateJob(IServiceProvider provider, OpenIddictPruningOptions? options = null)
    {
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == provider);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictPruningOptions>>(
            monitor => monitor.CurrentValue == (options ?? new OpenIddictPruningOptions()));
        var logger = Mock.Of<ILogger<OpenIddictPruningBackgroundService>>();

        return new OpenIddictPruningBackgroundService(monitor, Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory), logger);
    }
}
