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
        public void DisableAuthorizationsPruning_AuthorizationsPruningIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableAuthorizationsPruning();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.DisableAuthorizationsPruning);
        }

        [Fact]
        public void DisableTokensPruning_TokensPruningIsDisabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.DisableTokensPruning();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.DisableTokensPruning);
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
