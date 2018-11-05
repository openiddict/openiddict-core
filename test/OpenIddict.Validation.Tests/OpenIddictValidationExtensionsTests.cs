/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
        public void AddValidation_RegistersAuthenticationServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IAuthenticationService));
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
        public void AddValidation_RegistersHandler()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(OpenIddictValidationHandler) &&
                                                 service.ImplementationType == typeof(OpenIddictValidationHandler));
        }

        [Fact]
        public void AddValidation_RegistersProvider()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(OpenIddictValidationProvider) &&
                                                 service.ImplementationType == typeof(OpenIddictValidationProvider));
        }

        [Theory]
        [InlineData(typeof(IPostConfigureOptions<OpenIddictValidationOptions>), typeof(OpenIddictValidationConfiguration))]
        [InlineData(typeof(IPostConfigureOptions<OpenIddictValidationOptions>), typeof(OAuthValidationInitializer))]
        public void AddValidation_RegistersConfiguration(Type serviceType, Type implementationType)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            Assert.Contains(services, service => service.ServiceType == serviceType &&
                                                 service.ImplementationType == implementationType);
        }

        [Fact]
        public void AddValidation_RegistersAuthenticationScheme()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

            Assert.Contains(options.Schemes, scheme => scheme.Name == OpenIddictValidationDefaults.AuthenticationScheme &&
                                                       scheme.HandlerType == typeof(OpenIddictValidationHandler));
        }

        [Fact]
        public void AddValidation_ThrowsAnExceptionWhenSchemeIsAlreadyRegisteredWithDifferentHandlerType()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddOAuthValidation();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddValidation();

            // Assert
            var provider = services.BuildServiceProvider();
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                return provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The OpenIddict validation handler cannot be registered as an authentication scheme.")
                .AppendLine("This may indicate that an instance of the OAuth validation or JWT bearer handler was registered.")
                .Append("Make sure that neither 'services.AddAuthentication().AddOAuthValidation()' nor ")
                .Append("'services.AddAuthentication().AddJwtBearer()' are called from 'ConfigureServices'.")
                .ToString(), exception.Message);
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
    }
}
