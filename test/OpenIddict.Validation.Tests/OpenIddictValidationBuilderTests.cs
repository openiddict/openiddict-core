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
        public void AddEventHandler_HandlerIsAttached()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);
            var handler = new OpenIddictValidationEventHandler<CreateTicket>(
                (notification, cancellationToken) => Task.CompletedTask);

            // Act
            builder.AddEventHandler(handler);

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictValidationEventHandler<CreateTicket>) &&
                service.ImplementationInstance == handler);
        }

        [Fact]
        public void AddEventHandler_ThrowsAnExceptionForInvalidHandlerType()
        {
            // Arrange
            var services = CreateServices();
            var builder = CreateBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentException>(delegate
            {
                return builder.AddEventHandler<CreateTicket>(typeof(object));
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
            builder.AddEventHandler<CreateTicket, CustomHandler>();

            // Assert
            Assert.Contains(services, service =>
                service.ServiceType == typeof(IOpenIddictValidationEventHandler<CreateTicket>) &&
                service.ImplementationType == typeof(CustomHandler));
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

        public class CustomHandler : OpenIddictValidationEventHandler<CreateTicket>
        {
            public CustomHandler(Func<CreateTicket, CancellationToken, Task> handler) : base(handler)
            {
            }
        }
    }
}
