/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using static OpenIddict.Validation.OpenIddictValidationEvents;

namespace OpenIddict.Validation.Tests
{
    public class OpenIddictValidationBuilderTests
    {
        [Fact]
        public void Constructor_ThrowsAnExceptionForNullServices()
        {
            // Arrange
            var services = (IServiceCollection) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => new OpenIddictValidationBuilder(services));

            Assert.Equal("services", exception.ParamName);
        }

        [Fact]
        public void AddEventHandler_HandlerIsAttached()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddEventHandler<CreateTicket>(notification => Task.FromResult(OpenIddictValidationEventState.Handled));

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictValidationEventHandler<CreateTicket>) &&
                service.ImplementationInstance.GetType() == typeof(OpenIddictValidationEventHandler<CreateTicket>));
        }

        [Fact]
        public void AddEventHandler_ThrowsAnExceptionForUnsupportedLifetime()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.AddEventHandler<CustomHandler>(ServiceLifetime.Transient);
            });

            Assert.Equal("lifetime", exception.ParamName);
            Assert.StartsWith("Handlers cannot be registered as transient services.", exception.Message);
        }

        [Fact]
        public void AddEventHandler_ThrowsAnExceptionForOpenGenericHandlerType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.AddEventHandler(typeof(OpenIddictValidationEventHandler<>));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void AddEventHandler_ThrowsAnExceptionForNonHandlerType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.AddEventHandler(typeof(object));
            });

            Assert.Equal("type", exception.ParamName);
            Assert.StartsWith("The specified type is invalid.", exception.Message);
        }

        [Fact]
        public void AddEventHandler_HandlerIsRegistered()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddEventHandler<CustomHandler>(ServiceLifetime.Singleton);

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictValidationEventHandler<ApplyChallenge>) &&
                service.ImplementationType == typeof(CustomHandler) &&
                service.Lifetime == ServiceLifetime.Singleton);
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictValidationEventHandler<CreateTicket>) &&
                service.ImplementationType == typeof(CustomHandler) &&
                service.Lifetime == ServiceLifetime.Singleton);
        }

        [Fact]
        public void Configure_OptionsAreCorrectlyAmended()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.Configure(configuration => configuration.ClaimsIssuer = "custom_issuer");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("custom_issuer", options.ClaimsIssuer);
        }

        [Fact]
        public void AddAudiences_AudiencesAreAdded()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.AddAudiences("Fabrikam", "Contoso");

            var options = GetOptions(services);

            // Assert
            Assert.Equal(new[] { "Fabrikam", "Contoso" }, options.Audiences);
        }

        [Fact]
        public void EnableAuthorizationValidation_ValidationIsEnforced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.EnableAuthorizationValidation();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.EnableAuthorizationValidation);
        }

        [Fact]
        public void RemoveErrorDetails_IncludeErrorDetailsIsSetToFalse()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.RemoveErrorDetails();

            var options = GetOptions(services);

            // Assert
            Assert.False(options.IncludeErrorDetails);
        }

        [Fact]
        public void SetRealm_RealmIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.SetRealm("custom_realm");

            var options = GetOptions(services);

            // Assert
            Assert.Equal("custom_realm", options.Realm);
        }

        [Fact]
        public void UseDataProtectionProvider_DefaultProviderIsReplaced()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.UseDataProtectionProvider(new EphemeralDataProtectionProvider());

            var options = GetOptions(services);

            // Assert
            Assert.IsType<EphemeralDataProtectionProvider>(options.DataProtectionProvider);
        }

        [Fact]
        public void UseReferenceTokens_ReferenceTokensAreEnabled()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act
            builder.UseReferenceTokens();

            var options = GetOptions(services);

            // Assert
            Assert.True(options.UseReferenceTokens);
        }

        private static IServiceCollection CreateServices()
            => new ServiceCollection().AddOptions();

        private static OpenIddictValidationBuilder CreateBuilder(IServiceCollection services)
            => new OpenIddictValidationBuilder(services);

        private static OpenIddictValidationOptions GetOptions(IServiceCollection services)
        {
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>();
            return options.Get(OpenIddictValidationDefaults.AuthenticationScheme);
        }

        public class CustomHandler : IOpenIddictValidationEventHandler<ApplyChallenge>,
                                     IOpenIddictValidationEventHandler<CreateTicket>
        {
            public Task<OpenIddictValidationEventState> HandleAsync(ApplyChallenge notification)
            {
                throw new NotImplementedException();
            }

            public Task<OpenIddictValidationEventState> HandleAsync(CreateTicket notification)
            {
                throw new NotImplementedException();
            }
        }
    }
}
