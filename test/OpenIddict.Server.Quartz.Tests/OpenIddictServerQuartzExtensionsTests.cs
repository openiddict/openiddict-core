using System;
using Microsoft.Extensions.DependencyInjection;
using Quartz;
using Xunit;

namespace OpenIddict.Server.Quartz.Tests
{
    public class OpenIddictServerQuartzExtensionsTests
    {
        [Fact]
        public void UseQuartz_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictServerBuilder) null!;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseQuartz());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void UseQuartz_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictServerBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseQuartz(configuration: null!));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void UseQuartz_RegistersJobService()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseQuartz();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(OpenIddictServerQuartzJob) &&
                service.ImplementationType == typeof(OpenIddictServerQuartzJob) &&
                service.Lifetime == ServiceLifetime.Transient);
        }

        [Fact]
        public void UseQuartz_RegistersJobDetails()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseQuartz();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IJobDetail) &&
                service.ImplementationInstance is IJobDetail job &&
                job.Key.Equals(OpenIddictServerQuartzJob.Identity));
        }

        [Fact]
        public void UseQuartz_RegistersTriggerDetails()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseQuartz();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(ITrigger) &&
                service.ImplementationInstance is ITrigger trigger &&
                trigger.JobKey.Equals(OpenIddictServerQuartzJob.Identity));
        }

        [Fact]
        public void UseQuartz_CanBeSafelyInvokedMultipleTimes()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseQuartz();
            builder.UseQuartz();
            builder.UseQuartz();

            // Assert
            Assert.Single(services, service => service.ServiceType == typeof(IJobDetail) &&
                service.ImplementationInstance is IJobDetail job &&
                job.Key.Equals(OpenIddictServerQuartzJob.Identity));

            Assert.Single(services, service => service.ServiceType == typeof(ITrigger) &&
                service.ImplementationInstance is ITrigger trigger &&
                trigger.JobKey.Equals(OpenIddictServerQuartzJob.Identity));
        }
    }
}
