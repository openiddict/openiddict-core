/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

public class OpenIddictCoreBackgroundServiceTests
{
    [Theory]
    [InlineData("logger")]
    [InlineData("options")]
    [InlineData("provider")]
    public void Constructor_ThrowsAnExceptionForNullDependencies(string parameter)
    {
        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictCoreBackgroundService(
            parameter is "logger" ? null! : Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(),
            parameter is "options" ? null! : Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(),
            parameter is "provider" ? null! : Mock.Of<IServiceProvider>()));

        Assert.Equal(parameter, exception.ParamName);
    }

    [Fact]
    public async Task ExecuteAsync_StopsWhenAllPruningIsDisabled()
    {
        // Arrange
        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticAuthorizationPruning = true,
            DisableAutomaticSessionPruning = true,
            DisableAutomaticTokenPruning = true
        };
        var factory = new Mock<IServiceScopeFactory>();
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory.Object);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await service.ExecuteTask!;

        // Assert
        factory.Verify(factory => factory.CreateScope(), Times.Never());
    }

    [Fact]
    public async Task ExecuteAsync_UsesAndDisposesServiceScope()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));
        var options = new OpenIddictCoreOptions { TimeProvider = clock.Object };
        var scope = new Mock<IServiceScope>();
        var factory = new Mock<IServiceScopeFactory>();
        var manager = new Mock<IOpenIddictSessionManager>();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => completion.SetResult(true)).Returns(new ValueTask<long>(0));
        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>() &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == manager.Object);
        scope.SetupGet(scope => scope.ServiceProvider).Returns(scoped);
        factory.Setup(factory => factory.CreateScope()).Returns(scope.Object);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory.Object);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        factory.Verify(factory => factory.CreateScope(), Times.Once());
        scope.Verify(scope => scope.Dispose(), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_SkipsTokenPruningWhenDisabled()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticTokenPruning = true,
            TimeProvider = clock.Object
        };

        var tokens = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        var sessions = new Mock<IOpenIddictSessionManager>();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        sessions.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => completion.SetResult(true)).Returns(new ValueTask<long>(0));

        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == authorizations.Object &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == sessions.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        tokens.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never());
        authorizations.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        sessions.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_SkipsAuthorizationPruningWhenDisabled()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticAuthorizationPruning = true,
            TimeProvider = clock.Object
        };

        var tokens = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        var sessions = new Mock<IOpenIddictSessionManager>();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        sessions.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => completion.SetResult(true)).Returns(new ValueTask<long>(0));

        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == authorizations.Object &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == sessions.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        tokens.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        authorizations.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never());
        sessions.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_SkipsSessionPruningWhenDisabled()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticSessionPruning = true,
            TimeProvider = clock.Object
        };

        var tokens = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        var sessions = new Mock<IOpenIddictSessionManager>();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        authorizations.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => completion.SetResult(true)).Returns(new ValueTask<long>(0));

        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == authorizations.Object &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == sessions.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        tokens.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        authorizations.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        sessions.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ExecuteAsync_PrunesTokensBeforeAuthorizationsAndSessionsUsingConfiguredThresholds()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));
        var options = new OpenIddictCoreOptions { TimeProvider = clock.Object };
        options.MinimumTokenLifespan = TimeSpan.FromDays(1);
        options.MinimumAuthorizationLifespan = TimeSpan.FromDays(2);
        options.MinimumSessionLifespan = TimeSpan.FromDays(3);
        var tokens = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        var sessions = new Mock<IOpenIddictSessionManager>();
        var calls = new List<string>();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        tokens.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback<DateTimeOffset, CancellationToken>((date, _) =>
            {
                Assert.Equal(options.TimeProvider.GetUtcNow() - options.MinimumTokenLifespan, date);
                calls.Add("token");
            }).Returns(new ValueTask<long>(0));
        authorizations.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback<DateTimeOffset, CancellationToken>((date, _) =>
            {
                Assert.Equal(options.TimeProvider.GetUtcNow() - options.MinimumAuthorizationLifespan, date);
                calls.Add("authorization");
            }).Returns(new ValueTask<long>(0));
        sessions.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback<DateTimeOffset, CancellationToken>((date, _) =>
            {
                Assert.Equal(options.TimeProvider.GetUtcNow() - options.MinimumSessionLifespan, date);
                calls.Add("session");
                completion.SetResult(true);
            }).Returns(new ValueTask<long>(0));
        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == authorizations.Object &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == sessions.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        Assert.Equal(["token", "authorization", "session"], calls);
    }

    [Fact]
    public async Task ExecuteAsync_RepeatsPruningOnTimerTicks()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));
        var options = new OpenIddictCoreOptions { TimeProvider = clock.Object };
        options.DisableAutomaticAuthorizationPruning = true;
        options.DisableAutomaticSessionPruning = true;
        var tokens = new Mock<IOpenIddictTokenManager>();
        var first = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var second = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var count = 0;
        tokens.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => (Interlocked.Increment(ref count) is 1 ? first : second).SetResult(true))
            .Returns(new ValueTask<long>(0));
        var factory = new Mock<IServiceScopeFactory>();
        factory.Setup(factory => factory.CreateScope())
            .Returns(() => Mock.Of<IServiceScope>(scope => scope.ServiceProvider ==
                Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object)));
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory.Object);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await first.Task.WaitAsync(TimeSpan.FromSeconds(5));
        clock.Object.Advance(TimeSpan.FromHours(1));
        await second.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        factory.Verify(factory => factory.CreateScope(), Times.Exactly(2));
        tokens.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    [Fact]
    public async Task ExecuteAsync_LogsNonFatalTokenPruningErrorsAndContinues()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions { TimeProvider = clock.Object };
        var tokens = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        var sessions = new Mock<IOpenIddictSessionManager>();
        var logger = new Mock<ILogger<OpenIddictCoreBackgroundService>>();
        var error = new ApplicationException();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        tokens.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(error);
        sessions.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => completion.SetResult(true)).Returns(new ValueTask<long>(0));

        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == authorizations.Object &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == sessions.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(logger.Object, monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        Assert.Contains(logger.Invocations, invocation => string.Equals(invocation.Method.Name, "Log", StringComparison.Ordinal) &&
            invocation.Arguments[0] is LogLevel.Information &&
            invocation.Arguments[1] is EventId id && id.Id is 6298 &&
            ReferenceEquals(invocation.Arguments[3], error));
        authorizations.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
        sessions.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_LogsNonFatalAuthorizationPruningErrorsAndContinues()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions { TimeProvider = clock.Object };
        var tokens = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        var sessions = new Mock<IOpenIddictSessionManager>();
        var logger = new Mock<ILogger<OpenIddictCoreBackgroundService>>();
        var error = new ApplicationException();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        authorizations.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(error);
        sessions.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => completion.SetResult(true)).Returns(new ValueTask<long>(0));

        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == authorizations.Object &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == sessions.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(logger.Object, monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        Assert.Contains(logger.Invocations, invocation => string.Equals(invocation.Method.Name, "Log", StringComparison.Ordinal) &&
            invocation.Arguments[0] is LogLevel.Information &&
            invocation.Arguments[1] is EventId id && id.Id is 6299 &&
            ReferenceEquals(invocation.Arguments[3], error));
        sessions.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_LogsNonFatalSessionPruningErrorsAndContinues()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions { TimeProvider = clock.Object };
        var tokens = new Mock<IOpenIddictTokenManager>();
        var authorizations = new Mock<IOpenIddictAuthorizationManager>();
        var sessions = new Mock<IOpenIddictSessionManager>();
        var logger = new Mock<ILogger<OpenIddictCoreBackgroundService>>();
        var error = new ApplicationException();
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        sessions.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Callback(() => completion.SetResult(true)).Throws(error);

        var scoped = Mock.Of<IServiceProvider>(provider =>
            provider.GetService(typeof(IOpenIddictTokenManager)) == tokens.Object &&
            provider.GetService(typeof(IOpenIddictAuthorizationManager)) == authorizations.Object &&
            provider.GetService(typeof(IOpenIddictSessionManager)) == sessions.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(logger.Object, monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await service.StopAsync(CancellationToken.None);

        // Assert
        Assert.Contains(logger.Invocations, invocation => string.Equals(invocation.Method.Name, "Log", StringComparison.Ordinal) &&
            invocation.Arguments[0] is LogLevel.Information &&
            invocation.Arguments[1] is EventId id && id.Id is 6300 &&
            ReferenceEquals(invocation.Arguments[3], error));
        sessions.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_RethrowsOutOfMemoryExceptionsThrownDuringTokenPruning()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticAuthorizationPruning = true,
            DisableAutomaticSessionPruning = true,
            TimeProvider = clock.Object
        };

        var manager = new Mock<IOpenIddictTokenManager>();
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(new OutOfMemoryException());

        var scoped = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));

        // Assert
        await Assert.ThrowsAsync<OutOfMemoryException>(async () =>
            await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System));
    }

    [Fact]
    public async Task ExecuteAsync_RethrowsOutOfMemoryExceptionsThrownDuringAuthorizationPruning()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticTokenPruning = true,
            DisableAutomaticSessionPruning = true,
            TimeProvider = clock.Object
        };

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(new OutOfMemoryException());

        var scoped = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));

        // Assert
        await Assert.ThrowsAsync<OutOfMemoryException>(async () =>
            await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System));
    }

    [Fact]
    public async Task ExecuteAsync_RethrowsOutOfMemoryExceptionsThrownDuringSessionPruning()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticTokenPruning = true,
            DisableAutomaticAuthorizationPruning = true,
            TimeProvider = clock.Object
        };

        var manager = new Mock<IOpenIddictSessionManager>();
        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Throws(new OutOfMemoryException());

        var scoped = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IOpenIddictSessionManager)) == manager.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));

        // Assert
        await Assert.ThrowsAsync<OutOfMemoryException>(async () =>
            await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System));
    }

    [Fact]
    public async Task ExecuteAsync_StopsWhenTokenPruningIsCanceled()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticAuthorizationPruning = true,
            DisableAutomaticSessionPruning = true,
            TimeProvider = clock.Object
        };

        var manager = new Mock<IOpenIddictTokenManager>();
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);

        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns((DateTimeOffset _, CancellationToken token) =>
            {
                token.Register(() => canceled.TrySetCanceled(token));
                started.SetResult(true);
                return new ValueTask<long>(canceled.Task);
            });

        var scoped = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        await service.StopAsync(CancellationToken.None);
        await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);

        // Assert
        manager.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_StopsWhenAuthorizationPruningIsCanceled()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticTokenPruning = true,
            DisableAutomaticSessionPruning = true,
            TimeProvider = clock.Object
        };

        var manager = new Mock<IOpenIddictAuthorizationManager>();
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);

        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns((DateTimeOffset _, CancellationToken token) =>
            {
                token.Register(() => canceled.TrySetCanceled(token));
                started.SetResult(true);
                return new ValueTask<long>(canceled.Task);
            });

        var scoped = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        await service.StopAsync(CancellationToken.None);
        await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);

        // Assert
        manager.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_StopsWhenSessionPruningIsCanceled()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticTokenPruning = true,
            DisableAutomaticAuthorizationPruning = true,
            TimeProvider = clock.Object
        };

        var manager = new Mock<IOpenIddictSessionManager>();
        var started = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);

        manager.Setup(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()))
            .Returns((DateTimeOffset _, CancellationToken token) =>
            {
                token.Register(() => canceled.TrySetCanceled(token));
                started.SetResult(true);
                return new ValueTask<long>(canceled.Task);
            });

        var scoped = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IOpenIddictSessionManager)) == manager.Object);
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        await service.StopAsync(CancellationToken.None);
        await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);

        // Assert
        manager.Verify(manager => manager.PruneAsync(It.IsAny<DateTimeOffset>(), It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_FailsWhenTokenManagerIsMissing()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticAuthorizationPruning = true,
            DisableAutomaticSessionPruning = true,
            TimeProvider = clock.Object
        };

        var scoped = new Mock<IServiceProvider>();
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped.Object);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));

        // Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System));
        scoped.Verify(provider => provider.GetService(typeof(IOpenIddictTokenManager)), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_FailsWhenAuthorizationManagerIsMissing()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticTokenPruning = true,
            DisableAutomaticSessionPruning = true,
            TimeProvider = clock.Object
        };

        var scoped = new Mock<IServiceProvider>();
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped.Object);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));

        // Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System));
        scoped.Verify(provider => provider.GetService(typeof(IOpenIddictAuthorizationManager)), Times.Once());
    }

    [Fact]
    public async Task ExecuteAsync_FailsWhenSessionManagerIsMissing()
    {
        // Arrange
        var clock = new Mock<FakeTimeProvider> { CallBase = true };
        var timer = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        clock.Setup(clock => clock.CreateTimer(It.IsAny<TimerCallback>(), It.IsAny<object?>(),
                It.IsAny<TimeSpan>(), It.IsAny<TimeSpan>()))
            .CallBase().Callback(() => timer.TrySetResult(true));

        var options = new OpenIddictCoreOptions
        {
            DisableAutomaticTokenPruning = true,
            DisableAutomaticAuthorizationPruning = true,
            TimeProvider = clock.Object
        };

        var scoped = new Mock<IServiceProvider>();
        var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == scoped.Object);
        var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
        var provider = Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory);
        var monitor = Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(monitor => monitor.CurrentValue == options);
        using var service = new OpenIddictCoreBackgroundService(
            Mock.Of<ILogger<OpenIddictCoreBackgroundService>>(), monitor, provider);

        // Act
        await service.StartAsync(CancellationToken.None);
        await timer.Task.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System);
        clock.Object.Advance(TimeSpan.FromMinutes(10));

        // Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await service.ExecuteTask!.WaitAsync(TimeSpan.FromSeconds(5), TimeProvider.System));
        scoped.Verify(provider => provider.GetService(typeof(IOpenIddictSessionManager)), Times.Once());
    }
}
