/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Data.Entity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using OpenIddict.EntityFramework.Models;
using Xunit;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.EntityFramework.Tests
{
    public class OpenIddictEntityFrameworkBuilderTests
    {
        [Fact]
        public void Constructor_ThrowsAnExceptionForNullServices()
        {
            // Arrange
            var services = (IServiceCollection) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictEntityFrameworkBuilder(services));

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
        public void UseDbContext_ThrowsAnExceptionForNullType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(delegate
            {
                return builder.UseDbContext(type: null);
            });

            Assert.Equal("type", exception.ParamName);
        }

        [Fact]
        public void UseDbContext_ThrowsAnExceptionForInvalidType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.UseDbContext(typeof(object));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith(SR.GetResourceString(SR.ID1231), exception.Message);
        }

        [Fact]
        public void UseDbContext_RegistersDbContextAsScopedService()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.UseDbContext<CustomDbContext>();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(CustomDbContext) &&
                                                 service.ImplementationType == typeof(CustomDbContext));
        }

        [Fact]
        public void UseDbContext_SetsDbContextTypeInOptions()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.UseDbContext<CustomDbContext>();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictEntityFrameworkOptions>>().CurrentValue;

            Assert.Equal(typeof(CustomDbContext), options.DbContextType);
        }

        private static OpenIddictEntityFrameworkBuilder CreateBuilder(IServiceCollection services)
            => services.AddOpenIddict().AddCore().UseEntityFramework();

        private static IServiceCollection CreateServices()
        {
            var services = new ServiceCollection();
            services.AddOptions();

            return services;
        }

        public class CustomApplication : OpenIddictEntityFrameworkApplication<long, CustomAuthorization, CustomToken> { }
        public class CustomAuthorization : OpenIddictEntityFrameworkAuthorization<long, CustomApplication, CustomToken> { }
        public class CustomScope : OpenIddictEntityFrameworkScope<long> { }
        public class CustomToken : OpenIddictEntityFrameworkToken<long, CustomApplication, CustomAuthorization> { }

        public class CustomDbContext : DbContext
        {
            public CustomDbContext(string nameOrConnectionString)
                : base(nameOrConnectionString)
            {
            }
        }
    }
}
