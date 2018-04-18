/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests
{
    public class OpenIddictExtensionsTests
    {
        public void UseDefaultModels_KeyTypeDefaultsToString()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = services.AddOpenIddict().AddCore();

            // Act
            builder.UseDefaultModels();

            // Assert
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(OpenIddictApplication), options.DefaultApplicationType);
            Assert.Equal(typeof(OpenIddictAuthorization), options.DefaultAuthorizationType);
            Assert.Equal(typeof(OpenIddictScope), options.DefaultScopeType);
            Assert.Equal(typeof(OpenIddictToken), options.DefaultTokenType);
        }

        public void UseDefaultModels_KeyTypeCanBeOverriden()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = services.AddOpenIddict().AddCore();

            // Act
            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictCoreOptions>>().CurrentValue;

            Assert.Equal(typeof(OpenIddictApplication<Guid>), options.DefaultApplicationType);
            Assert.Equal(typeof(OpenIddictAuthorization<Guid>), options.DefaultAuthorizationType);
            Assert.Equal(typeof(OpenIddictScope<Guid>), options.DefaultScopeType);
            Assert.Equal(typeof(OpenIddictToken<Guid>), options.DefaultTokenType);
        }
    }
}
