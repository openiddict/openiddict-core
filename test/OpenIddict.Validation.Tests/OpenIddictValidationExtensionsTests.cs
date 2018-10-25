/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Builder.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.Internal;
using Xunit;

namespace OpenIddict.Validation.Tests
{
    public class OpenIddictValidationExtensionsTests
    {
        [Fact]
        public void AddValidation_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.AddValidation());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void AddValidation_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.AddValidation(configuration: null));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void AddValidation_RegistersLoggingServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(ILogger<>));
        }

        [Fact]
        public void AddValidation_RegistersOptionsServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IOptions<>));
        }

        [Fact]
        public void AddValidation_RegistersEventService()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(IOpenIddictValidationEventDispatcher) &&
                                                 service.ImplementationType == typeof(OpenIddictValidationEventDispatcher));
        }

        [Fact]
        public void AddValidation_CanBeSafelyInvokedMultipleTimes()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act and assert
            builder.AddValidation();
            builder.AddValidation();
            builder.AddValidation();
        }

        [Fact]
        public void UseOpenIddictValidation_ThrowsAnExceptionWhenEventsAreNull()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOpenIddict()
                .AddValidation()
                    .Configure(options => options.Events = null);

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictValidation());

            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in validation provider.")
                .AppendLine("This error may indicate that 'OpenIddictValidationOptions.Events' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddValidation().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void UseOpenIddictValidation_ThrowsAnExceptionWhenEventsTypeIsIncompatible()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOpenIddict()
                .AddValidation()
                    .Configure(options => options.Events = new OAuthValidationEvents());

            var builder = new ApplicationBuilder(services.BuildServiceProvider());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => builder.UseOpenIddictValidation());

            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in validation provider.")
                .AppendLine("This error may indicate that 'OpenIddictValidationOptions.Events' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddValidation().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }
    }
}
