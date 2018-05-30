/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using AspNet.Security.OpenIdConnect.Client;
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
        public async Task PostConfigure_ThrowsAnExceptionWhenApplicationEventsTypeAndInstanceAreProvided()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options =>
                {
                    options.ApplicationEvents = new OAuthValidationEvents();
                    options.ApplicationEventsType = typeof(OAuthValidationEvents);
                });
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal("Application events cannot be registered when a type is specified.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionForInvalidApplicationEventsType()
        {
            // Arrange
            var server = CreateAuthorizationServer(builder =>
            {
                builder.Configure(options => options.ApplicationEventsType = typeof(object));
            });

            var client = new OpenIdConnectClient(server.CreateClient());

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            // Assert
            Assert.Equal("Application events must inherit from OAuthValidationEvents.", exception.Message);
        }

        private static TestServer CreateAuthorizationServer(Action<OpenIddictValidationBuilder> configuration = null)
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
                    .AddCore(options =>
                    {
                        options.SetDefaultApplicationEntity<OpenIddictApplication>()
                               .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                               .SetDefaultScopeEntity<OpenIddictScope>()
                               .SetDefaultTokenEntity<OpenIddictToken>();
                    })

                    .AddValidation(options => configuration?.Invoke(options));
            });

            builder.Configure(app =>
            {
                app.UseAuthentication();

                app.Run(context => context.ChallengeAsync(OpenIddictValidationDefaults.AuthenticationScheme));
            });

            return new TestServer(builder);
        }

        public class OpenIddictApplication { }
        public class OpenIddictAuthorization { }
        public class OpenIddictScope { }
        public class OpenIddictToken { }
    }
}
