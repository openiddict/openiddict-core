/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Server.Tests
{
    public class OpenIddictServerExtensionsTests
    {
        [Fact]
        public void AddServer_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.AddServer());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void AddServer_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.AddServer(configuration: null));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void AddServer_RegistersAuthenticationServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IAuthenticationService));
        }

        [Fact]
        public void AddServer_RegistersCachingServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IDistributedCache));
            Assert.Contains(services, service => service.ServiceType == typeof(IMemoryCache));
        }

        [Fact]
        public void AddServer_RegistersLoggingServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(ILogger<>));
        }

        [Fact]
        public void AddServer_RegistersOptionsServices()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IOptions<>));
        }

        [Fact]
        public void AddServer_RegistersEventService()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(IOpenIddictServerEventDispatcher) &&
                                                 service.ImplementationType == typeof(OpenIddictServerEventDispatcher));
        }

        [Fact]
        public void AddServer_RegistersHandler()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(OpenIddictServerHandler) &&
                                                 service.ImplementationType == typeof(OpenIddictServerHandler));
        }

        [Fact]
        public void AddServer_RegistersProvider()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.Lifetime == ServiceLifetime.Scoped &&
                                                 service.ServiceType == typeof(OpenIddictServerProvider) &&
                                                 service.ImplementationFactory != null);
        }

        [Fact]
        public void AddServer_ResolvingProviderThrowsAnExceptionWhenCoreServicesAreNotRegistered()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            var provider = services.BuildServiceProvider();

            var exception = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<OpenIddictServerProvider>());

            Assert.Equal(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server handler.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .Append("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .ToString(), exception.Message);
        }

        [Theory]
        [InlineData(typeof(IPostConfigureOptions<OpenIddictServerOptions>), typeof(OpenIddictServerConfiguration))]
        [InlineData(typeof(IPostConfigureOptions<OpenIddictServerOptions>), typeof(OpenIdConnectServerInitializer))]
        public void AddServer_RegistersConfiguration(Type serviceType, Type implementationType)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            Assert.Contains(services, service => service.ServiceType == serviceType &&
                                                 service.ImplementationType == implementationType);
        }

        [Fact]
        public void AddServer_RegistersAuthenticationScheme()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;

            Assert.Contains(options.Schemes, scheme => scheme.Name == OpenIddictServerDefaults.AuthenticationScheme &&
                                                       scheme.HandlerType == typeof(OpenIddictServerHandler));
        }

        [Fact]
        public void AddServer_ThrowsAnExceptionWhenSchemeIsAlreadyRegisteredWithDifferentHandlerType()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddAuthentication()
                .AddOpenIdConnectServer();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddServer();

            // Assert
            var provider = services.BuildServiceProvider();
            var exception = Assert.Throws<InvalidOperationException>(delegate
            {
                return provider.GetRequiredService<IOptions<AuthenticationOptions>>().Value;
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The OpenIddict server handler cannot be registered as an authentication scheme.")
                .AppendLine("This may indicate that an instance of the OpenID Connect server was registered.")
                .Append("Make sure that 'services.AddAuthentication().AddOpenIdConnectServer()' is not used.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void AddServer_CanBeSafelyInvokedMultipleTimes()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictBuilder(services);

            // Act and assert
            builder.AddServer();
            builder.AddServer();
            builder.AddServer();
        }
    }
}
