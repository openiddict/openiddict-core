/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Validation.Tests
{
    public class OpenIddictValidationConfigurationTests
    {
        [Fact]
        public void Configure_ThrowsAnExceptionForNullOptions()
        {
            // Arrange
            var configuration = new OpenIddictValidationConfiguration(Mock.Of<IDataProtectionProvider>());

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => configuration.Configure(null));

            Assert.Equal("options", exception.ParamName);
        }

        [Theory]
        [InlineData(new object[] { new string[] { OpenIddictValidationDefaults.AuthenticationScheme, null } })]
        [InlineData(new object[] { new string[] { null, OpenIddictValidationDefaults.AuthenticationScheme } })]
        public void PostConfigure_ThrowsAnExceptionWhenDefaultSchemesPointToValidationHandler(string[] schemes)
        {
            // Arrange
            var options = new AuthenticationOptions
            {
                DefaultSignInScheme = schemes[0],
                DefaultSignOutScheme = schemes[1]
            };

            options.AddScheme<OpenIddictValidationHandler>(OpenIddictValidationDefaults.AuthenticationScheme, displayName: null);

            var configuration = new OpenIddictValidationConfiguration(Mock.Of<IDataProtectionProvider>());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => configuration.PostConfigure(Options.DefaultName, options));

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendLine("The OpenIddict validation handler cannot be used as the default sign-in/out scheme handler.")
                .Append("Make sure that neither DefaultSignInScheme nor DefaultSignOutScheme ")
                .Append("point to an instance of the OpenIddict validation handler.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void Configure_ThrowsAnExceptionWhenSchemeIsAlreadyRegisteredWithDifferentHandlerType()
        {
            // Arrange
            var options = new AuthenticationOptions();
            options.AddScheme(OpenIddictValidationDefaults.AuthenticationScheme, builder =>
            {
                builder.HandlerType = typeof(OAuthValidationHandler);
            });

            var configuration = new OpenIddictValidationConfiguration(Mock.Of<IDataProtectionProvider>());

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => configuration.Configure(options));

            Assert.Equal(new StringBuilder()
                .AppendLine("The OpenIddict validation handler cannot be registered as an authentication scheme.")
                .AppendLine("This may indicate that an instance of the OAuth validation or JWT bearer handler was registered.")
                .Append("Make sure that neither 'services.AddAuthentication().AddOAuthValidation()' nor ")
                .Append("'services.AddAuthentication().AddJwtBearer()' are called from 'ConfigureServices'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenEventsTypeIsNull()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.EventsType = null);
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in validation provider.")
                .AppendLine("This error may indicate that 'OpenIddictValidationOptions.EventsType' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddValidation().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionWhenEventsTypeIsIncompatible()
        {
            // Arrange
            var server = CreateResourceServer(builder =>
            {
                builder.Configure(options => options.EventsType = typeof(OAuthValidationEvents));
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal(new StringBuilder()
                .AppendLine("OpenIddict can only be used with its built-in validation provider.")
                .AppendLine("This error may indicate that 'OpenIddictValidationOptions.EventsType' was manually set.")
                .Append("To execute custom request handling logic, consider registering an event handler using ")
                .Append("the generic 'services.AddOpenIddict().AddValidation().AddEventHandler()' method.")
                .ToString(), exception.Message);
        }

        private static TestServer CreateResourceServer(Action<OpenIddictValidationBuilder> configuration = null)
        {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddAuthentication();
                services.AddOptions();
                services.AddDistributedMemoryCache();

                services.AddOpenIddict()
                    .AddValidation(options => configuration?.Invoke(options));
            });

            builder.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(context => context.ChallengeAsync(OpenIddictValidationDefaults.AuthenticationScheme));
            });

            return new TestServer(builder);
        }
    }
}
