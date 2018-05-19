/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using NHibernate;
using Xunit;

namespace OpenIddict.NHibernate.Tests
{
    public class OpenIddictNHibernateContextTests
    {
        [Fact]
        public async Task GetSessionAsync_ThrowsAnExceptionForCanceledToken()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>();
            var token = new CancellationToken(canceled: true);

            var context = new OpenIddictNHibernateContext(options, provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<TaskCanceledException>(async delegate
            {
                await context.GetSessionAsync(token);
            });

            Assert.Equal(token, exception.CancellationToken);
        }

        [Fact]
        public async Task GetSessionAsync_UsesSessionRegisteredInDependencyInjectionContainer()
        {
            // Arrange
            var services = new ServiceCollection();

            var session = new Mock<ISession>();
            var factory = new Mock<ISessionFactory>();

            services.AddSingleton(session.Object);
            services.AddSingleton(factory.Object);

            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>(
                mock => mock.CurrentValue == new OpenIddictNHibernateOptions
                {
                    SessionFactory = null
                });

            var context = new OpenIddictNHibernateContext(options, provider);

            // Act and assert
            Assert.Same(session.Object, await context.GetSessionAsync(CancellationToken.None));
            factory.Verify(mock => mock.OpenSession(), Times.Never());
        }

        [Theory]
        [InlineData(FlushMode.Always)]
        [InlineData(FlushMode.Auto)]
        [InlineData(FlushMode.Commit)]
        [InlineData(FlushMode.Unspecified)]
        public async Task GetSessionAsync_CreatesSubSessionWhenFlushModeIsNotManual(FlushMode mode)
        {
            // Arrange
            var services = new ServiceCollection();

            var session = new Mock<ISession>();
            session.SetupProperty(mock => mock.FlushMode, mode);

            var builder = new Mock<ISharedSessionBuilder>();
            builder.Setup(mock => mock.AutoClose())
                .Returns(builder.Object);
            builder.Setup(mock => mock.AutoJoinTransaction())
                .Returns(builder.Object);
            builder.Setup(mock => mock.Connection())
                .Returns(builder.Object);
            builder.Setup(mock => mock.ConnectionReleaseMode())
                .Returns(builder.Object);
            builder.Setup(mock => mock.FlushMode(FlushMode.Manual))
                .Returns(builder.Object);
            builder.Setup(mock => mock.Interceptor())
                .Returns(builder.Object);
            builder.Setup(mock => mock.OpenSession())
                .Returns(session.Object);

            session.Setup(mock => mock.SessionWithOptions())
                .Returns(builder.Object);

            var factory = new Mock<ISessionFactory>();

            services.AddSingleton(session.Object);
            services.AddSingleton(factory.Object);

            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>(
                mock => mock.CurrentValue == new OpenIddictNHibernateOptions
                {
                    SessionFactory = null
                });

            var context = new OpenIddictNHibernateContext(options, provider);

            // Act and assert
            Assert.Same(session.Object, await context.GetSessionAsync(CancellationToken.None));
            builder.Verify(mock => mock.AutoClose(), Times.Once());
            builder.Verify(mock => mock.AutoJoinTransaction(), Times.Once());
            builder.Verify(mock => mock.Connection(), Times.Once());
            builder.Verify(mock => mock.ConnectionReleaseMode(), Times.Once());
            builder.Verify(mock => mock.FlushMode(FlushMode.Manual), Times.Once());
            builder.Verify(mock => mock.Interceptor(), Times.Once());
            builder.Verify(mock => mock.OpenSession(), Times.Once());
            factory.Verify(mock => mock.OpenSession(), Times.Never());
        }

        [Fact]
        public async Task GetSessionAsync_UsesSessionFactoryRegisteredInDependencyInjectionContainer()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<ISessionFactory>());

            var session = new Mock<ISession>();
            var factory = new Mock<ISessionFactory>();
            factory.Setup(mock => mock.OpenSession())
                .Returns(session.Object);

            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>(
                mock => mock.CurrentValue == new OpenIddictNHibernateOptions
                {
                    SessionFactory = factory.Object
                });

            var context = new OpenIddictNHibernateContext(options, provider);

            // Act and assert
            Assert.Same(session.Object, await context.GetSessionAsync(CancellationToken.None));
            factory.Verify(mock => mock.OpenSession(), Times.Once());
            session.VerifySet(mock => mock.FlushMode = FlushMode.Manual, Times.Once());
        }

        [Fact]
        public async Task GetSessionAsync_ThrowsAnExceptionWhenSessionFactoryCannotBeFound()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>(
                mock => mock.CurrentValue == new OpenIddictNHibernateOptions
                {
                    SessionFactory = null
                });

            var context = new OpenIddictNHibernateContext(options, provider);

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async delegate
            {
                await context.GetSessionAsync(CancellationToken.None);
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("No suitable NHibernate session or session factory can be found.")
                .Append("To configure the OpenIddict NHibernate stores to use a specific factory, use ")
                .Append("'services.AddOpenIddict().AddCore().UseNHibernate().UseSessionFactory()' or register an ")
                .Append("'ISession'/'ISessionFactory' in the dependency injection container in 'ConfigureServices()'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task GetSessionAsync_PrefersSessionFactoryRegisteredInOptionsToSessionRegisteredInDependencyInjectionContainer()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<ISessionFactory>());

            var session = new Mock<ISession>();
            var factory = new Mock<ISessionFactory>();
            factory.Setup(mock => mock.OpenSession())
                .Returns(session.Object);

            var provider = services.BuildServiceProvider();

            var options = Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>(
                mock => mock.CurrentValue == new OpenIddictNHibernateOptions
                {
                    SessionFactory = factory.Object
                });

            var context = new OpenIddictNHibernateContext(options, provider);

            // Act and assert
            Assert.Same(session.Object, await context.GetSessionAsync(CancellationToken.None));
            factory.Verify(mock => mock.OpenSession(), Times.Once());
            session.VerifySet(mock => mock.FlushMode = FlushMode.Manual, Times.Once());
        }

        [Fact]
        public async Task GetSessionAsync_ReturnsCachedSession()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();

            var factory = new Mock<ISessionFactory>();
            factory.Setup(mock => mock.OpenSession())
                .Returns(() => Mock.Of<ISession>());

            var options = Mock.Of<IOptionsMonitor<OpenIddictNHibernateOptions>>(
                mock => mock.CurrentValue == new OpenIddictNHibernateOptions
                {
                    SessionFactory = factory.Object
                });

            var context = new OpenIddictNHibernateContext(options, provider);

            // Act and assert
            Assert.Same(
                await context.GetSessionAsync(CancellationToken.None),
                await context.GetSessionAsync(CancellationToken.None));

            factory.Verify(mock => mock.OpenSession(), Times.Once());
        }
    }
}
