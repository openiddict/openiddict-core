/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using NHibernate;
using OpenIddict.Core;
using OpenIddict.NHibernate.Models;
using Xunit;

namespace OpenIddict.NHibernate.Tests
{
    public class OpenIddictNHibernateBuilderTests
    {
        [Fact]
        public void Constructor_ThrowsAnExceptionForNullServices()
        {
            // Arrange
            var services = (IServiceCollection) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictNHibernateBuilder(services));

            Assert.Equal("services", exception.ParamName);
        }

        [Fact]
        public void ReplaceDefaultEntities_EntitiesAreCorrectlyReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceDefaultEntities<CustomApplication, CustomAuthorization, CustomScope, CustomToken, long>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(CustomApplication), options.DefaultApplicationType);
            Assert.Equal(typeof(CustomAuthorization), options.DefaultAuthorizationType);
            Assert.Equal(typeof(CustomScope), options.DefaultScopeType);
            Assert.Equal(typeof(CustomToken), options.DefaultTokenType);
        }

        [Fact]
        public void ReplaceDefaultEntities_AllowsSpecifyingCustomKeyType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.ReplaceDefaultEntities<long>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(OpenIddictApplication<long>), options.DefaultApplicationType);
            Assert.Equal(typeof(OpenIddictAuthorization<long>), options.DefaultAuthorizationType);
            Assert.Equal(typeof(OpenIddictScope<long>), options.DefaultScopeType);
            Assert.Equal(typeof(OpenIddictToken<long>), options.DefaultTokenType);
        }

        [Fact]
        public void UseSessionFactory_ThrowsAnExceptionForNullFactory()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                return builder.UseSessionFactory(factory: null);
            });

            Assert.Equal("factory", exception.ParamName);
        }

        [Fact]
        public void UseSessionFactory_SetsDbContextTypeInOptions()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);
            var factory = Mock.Of<ISessionFactory>();

            // Act
            builder.UseSessionFactory(factory);

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictNHibernateOptions>>().CurrentValue;

            Assert.Same(factory, options.SessionFactory);
        }

        private static OpenIddictNHibernateBuilder CreateBuilder(IServiceCollection services)
            => services.AddOpenIddict().AddCore().UseNHibernate();

        private static IServiceCollection CreateServices()
        {
            var services = new ServiceCollection();
            services.AddOptions();

            return services;
        }

        public class CustomApplication : OpenIddictApplication<long, CustomAuthorization, CustomToken> { }
        public class CustomAuthorization : OpenIddictAuthorization<long, CustomApplication, CustomToken> { }
        public class CustomScope : OpenIddictScope<long> { }
        public class CustomToken : OpenIddictToken<long, CustomApplication, CustomAuthorization> { }
    }
}
