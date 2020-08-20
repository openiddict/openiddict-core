using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Server.Quartz.Tests
{
    public class OpenIddictServerQuartzBuilderTests
    {
        [Fact]
        public void Constructor_ThrowsAnExceptionForNullServices()
        {
            // Arrange
            var services = (IServiceCollection) null!;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictServerQuartzBuilder(services));

            Assert.Equal("services", exception.ParamName);
        }

        [Fact]
        public void Configure_DelegateIsCorrectlyRegistered()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);
            var configuration = new Action<OpenIddictServerQuartzOptions>(options => { });

            // Act
            builder.Configure(configuration);

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IConfigureOptions<OpenIddictServerQuartzOptions>) &&
                service.ImplementationInstance is ConfigureNamedOptions<OpenIddictServerQuartzOptions> options &&
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
        public void SetMaximumRefireCount_ThrowsAnExceptionForNegativeCount()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentOutOfRangeException>(() => builder.SetMaximumRefireCount(-1));

            Assert.Equal("count", exception.ParamName);
            Assert.StartsWith(SR.GetResourceString(SR.ID1278), exception.Message);
        }

        [Fact]
        public void SetMaximumRefireCount_MaximumRefireCountIsSet()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetMaximumRefireCount(42);

            var options = GetOptions(services);

            // Assert
            Assert.Equal(42, options.MaximumRefireCount);
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1279), exception.Message);
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
            Assert.StartsWith(SR.GetResourceString(SR.ID1279), exception.Message);
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

        private static OpenIddictServerQuartzBuilder CreateBuilder(IServiceCollection services)
            => new OpenIddictServerQuartzBuilder(services);

        private static OpenIddictServerQuartzOptions GetOptions(IServiceCollection services)
        {
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<OpenIddictServerQuartzOptions>>();
            return options.Value;
        }
    }
}
