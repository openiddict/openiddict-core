using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using OpenIddict.Abstractions;
using Quartz;
using Xunit;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.Quartz.Tests
{
    public class OpenIddictServerQuartzJobTests
    {
        [Fact]
        public void Constructor_ThrowsAnException()
        {
            // Arrange, act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => new OpenIddictServerQuartzJob());

            Assert.Equal(SR.GetResourceString(SR.ID1081), exception.Message);
        }

        [Fact]
        public async Task Execute_UsesServiceScope()
        {
            // Arrange
            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

            var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == provider);
            var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
            var monitor = Mock.Of<IOptionsMonitor<OpenIddictServerQuartzOptions>>(
                monitor => monitor.CurrentValue == new OpenIddictServerQuartzOptions());

            var job = new OpenIddictServerQuartzJob(monitor,
                Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory));

            // Act
            await job.Execute(Mock.Of<IJobExecutionContext>());

            Mock.Get(factory).Verify(factory => factory.CreateScope(), Times.Once());
            Mock.Get(scope).Verify(scope => scope.Dispose(), Times.Once());
        }

        [Fact]
        public async Task Execute_IgnoresPruningWhenAuthorizationsPruningIsDisabled()
        {
            // Arrange

            var manager = new Mock<IOpenIddictAuthorizationManager>();

            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

            var job = CreateJob(provider, new OpenIddictServerQuartzOptions
            {
                DisableAuthorizationsPruning = true
            });

            // Act
            await job.Execute(Mock.Of<IJobExecutionContext>());

            // Assert
            manager.Verify(manager => manager.PruneAsync(It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task Execute_IgnoresPruningWhenTokensPruningIsDisabled()
        {
            // Arrange

            var manager = new Mock<IOpenIddictAuthorizationManager>();

            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);

            var job = CreateJob(provider, new OpenIddictServerQuartzOptions
            {
                DisableTokensPruning = true
            });

            // Act
            await job.Execute(Mock.Of<IJobExecutionContext>());

            // Assert
            manager.Verify(manager => manager.PruneAsync(It.IsAny<CancellationToken>()), Times.Never());
        }

        [Fact]
        public async Task Execute_UnschedulesTriggersWhenAuthorizationManagerIsMissing()
        {
            // Arrange
            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == null);

            var job = CreateJob(provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<JobExecutionException>(() => job.Execute(Mock.Of<IJobExecutionContext>()));

            Assert.False(exception.RefireImmediately);
            Assert.True(exception.UnscheduleAllTriggers);
            Assert.True(exception.UnscheduleFiringTrigger);

            Assert.IsType<InvalidOperationException>(exception.InnerException);
            Assert.Equal(SR.GetResourceString(SR.ID1277), exception.InnerException!.Message);
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
            var exception = await Assert.ThrowsAsync<JobExecutionException>(() => job.Execute(Mock.Of<IJobExecutionContext>()));

            Assert.False(exception.RefireImmediately);
            Assert.True(exception.UnscheduleAllTriggers);
            Assert.True(exception.UnscheduleFiringTrigger);

            Assert.IsType<InvalidOperationException>(exception.InnerException);
            Assert.Equal(SR.GetResourceString(SR.ID1277), exception.InnerException!.Message);
        }

        [Fact]
        public async Task Execute_RethrowsOutOfMemoryExceptionsThrownDuringAuthorizationsPruning()
        {
            // Arrange
            var manager = new Mock<IOpenIddictAuthorizationManager>();
            manager.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                .Throws(new OutOfMemoryException());

            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

            var job = CreateJob(provider);

            // Act and assert
            await Assert.ThrowsAsync<OutOfMemoryException>(() => job.Execute(Mock.Of<IJobExecutionContext>()));
        }

        [Fact]
        public async Task Execute_RethrowsOutOfMemoryExceptionsThrownDuringTokensPruning()
        {
            // Arrange
            var manager = new Mock<IOpenIddictTokenManager>();
            manager.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                .Throws(new OutOfMemoryException());

            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);

            var job = CreateJob(provider);

            // Act and assert
            await Assert.ThrowsAsync<OutOfMemoryException>(() => job.Execute(Mock.Of<IJobExecutionContext>()));
        }

        [Fact]
        public async Task Execute_DisablesRefiringWhenJobIsCanceledDuringAuthorizationsPruning()
        {
            // Arrange
            var token = new CancellationToken(canceled: true);

            var manager = new Mock<IOpenIddictAuthorizationManager>();
            manager.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                .Throws(new OperationCanceledException(token));

            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

            var context = Mock.Of<IJobExecutionContext>(context => context.CancellationToken == token);

            var job = CreateJob(provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<JobExecutionException>(() => job.Execute(context));

            Assert.False(exception.RefireImmediately);

            manager.Verify(manager => manager.PruneAsync(It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task Execute_DisablesRefiringWhenJobIsCanceledDuringTokensPruning()
        {
            // Arrange
            var token = new CancellationToken(canceled: true);

            var manager = new Mock<IOpenIddictTokenManager>();
            manager.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                .Throws(new OperationCanceledException(token));

            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == Mock.Of<IOpenIddictAuthorizationManager>() &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == manager.Object);

            var context = Mock.Of<IJobExecutionContext>(context => context.CancellationToken == token);

            var job = CreateJob(provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<JobExecutionException>(() => job.Execute(context));

            Assert.False(exception.RefireImmediately);

            manager.Verify(manager => manager.PruneAsync(It.IsAny<CancellationToken>()), Times.Once());
        }

        [Fact]
        public async Task Execute_AllowsRefiringWhenExceptionsAreThrown()
        {
            // Arrange
            var provider = new Mock<IServiceProvider>();
            provider.Setup(provider => provider.GetService(typeof(IOpenIddictAuthorizationManager)))
                .Returns(CreateAuthorizationManager(new ApplicationException()));

            provider.Setup(provider => provider.GetService(typeof(IOpenIddictTokenManager)))
                .Returns(CreateTokenManager(new ApplicationException()));

            var context = Mock.Of<IJobExecutionContext>(context => context.RefireCount == 0);

            var job = CreateJob(provider.Object);

            // Act and assert
            var exception = await Assert.ThrowsAsync<JobExecutionException>(() => job.Execute(context));

            Assert.True(exception.RefireImmediately);
            Assert.IsType<AggregateException>(exception.InnerException);
            Assert.Equal(2, ((AggregateException) exception.InnerException!).InnerExceptions.Count);
            Assert.IsType<ApplicationException>(((AggregateException) exception.InnerException!).InnerExceptions[0]);
            Assert.IsType<ApplicationException>(((AggregateException) exception.InnerException!).InnerExceptions[1]);

            static IOpenIddictAuthorizationManager CreateAuthorizationManager(Exception exception)
            {
                var mock = new Mock<IOpenIddictAuthorizationManager>();
                mock.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                    .Throws(exception);

                return mock.Object;
            }

            static IOpenIddictTokenManager CreateTokenManager(Exception exception)
            {
                var mock = new Mock<IOpenIddictTokenManager>();
                mock.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                    .Throws(exception);

                return mock.Object;
            }
        }

        [Fact]
        public async Task Execute_AllowsRefiringWhenAggregateExceptionsAreThrown()
        {
            // Arrange
            var provider = new Mock<IServiceProvider>();
            provider.Setup(provider => provider.GetService(typeof(IOpenIddictAuthorizationManager)))
                .Returns(CreateAuthorizationManager(new AggregateException(
                    new InvalidOperationException(), new ApplicationException())));

            provider.Setup(provider => provider.GetService(typeof(IOpenIddictTokenManager)))
                .Returns(CreateTokenManager(new AggregateException(
                    new InvalidOperationException(), new ApplicationException())));

            var context = Mock.Of<IJobExecutionContext>(context => context.RefireCount == 0);

            var job = CreateJob(provider.Object);

            // Act and assert
            var exception = await Assert.ThrowsAsync<JobExecutionException>(() => job.Execute(context));

            Assert.True(exception.RefireImmediately);
            Assert.IsType<AggregateException>(exception.InnerException);
            Assert.Equal(4, ((AggregateException) exception.InnerException!).InnerExceptions.Count);
            Assert.IsType<InvalidOperationException>(((AggregateException) exception.InnerException!).InnerExceptions[0]);
            Assert.IsType<ApplicationException>(((AggregateException) exception.InnerException!).InnerExceptions[1]);
            Assert.IsType<InvalidOperationException>(((AggregateException) exception.InnerException!).InnerExceptions[2]);
            Assert.IsType<ApplicationException>(((AggregateException) exception.InnerException!).InnerExceptions[3]);

            static IOpenIddictAuthorizationManager CreateAuthorizationManager(Exception exception)
            {
                var mock = new Mock<IOpenIddictAuthorizationManager>();
                mock.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                    .Throws(exception);

                return mock.Object;
            }

            static IOpenIddictTokenManager CreateTokenManager(Exception exception)
            {
                var mock = new Mock<IOpenIddictTokenManager>();
                mock.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                    .Throws(exception);

                return mock.Object;
            }
        }

        [Fact]
        public async Task Execute_DisallowsRefiringWhenMaximumRefireCountIsReached()
        {
            // Arrange
            var manager = new Mock<IOpenIddictAuthorizationManager>();
            manager.Setup(manager => manager.PruneAsync(It.IsAny<CancellationToken>()))
                .Throws(new ApplicationException());

            var provider = Mock.Of<IServiceProvider>(provider =>
                provider.GetService(typeof(IOpenIddictAuthorizationManager)) == manager.Object &&
                provider.GetService(typeof(IOpenIddictTokenManager)) == Mock.Of<IOpenIddictTokenManager>());

            var context = Mock.Of<IJobExecutionContext>(context => context.RefireCount == 5);

            var job = CreateJob(provider, new OpenIddictServerQuartzOptions
            {
                MaximumRefireCount = 5
            });

            // Act and assert
            var exception = await Assert.ThrowsAsync<JobExecutionException>(() => job.Execute(context));

            Assert.False(exception.RefireImmediately);
        }

        private static OpenIddictServerQuartzJob CreateJob(IServiceProvider provider, OpenIddictServerQuartzOptions? options = null)
        {
            var scope = Mock.Of<IServiceScope>(scope => scope.ServiceProvider == provider);
            var factory = Mock.Of<IServiceScopeFactory>(factory => factory.CreateScope() == scope);
            var monitor = Mock.Of<IOptionsMonitor<OpenIddictServerQuartzOptions>>(
                monitor => monitor.CurrentValue == (options ?? new OpenIddictServerQuartzOptions()));

            return new OpenIddictServerQuartzJob(monitor,
                Mock.Of<IServiceProvider>(provider => provider.GetService(typeof(IServiceScopeFactory)) == factory));
        }
    }
}
