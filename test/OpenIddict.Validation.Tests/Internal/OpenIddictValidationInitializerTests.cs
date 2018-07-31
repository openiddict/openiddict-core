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
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace OpenIddict.Validation.Tests
{
    public class OpenIddictValidationInitializerTests
    {
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
