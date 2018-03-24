/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Core;
using OpenIddict.Models;
using Xunit;

namespace OpenIddict.Tests
{
    public class OpenIddictExtensionsTests
    {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<OpenIddictApplication>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<OpenIddictAuthorization>))]
        [InlineData(typeof(OpenIddictScopeManager<OpenIddictScope>))]
        [InlineData(typeof(OpenIddictTokenManager<OpenIddictToken>))]
        public void AddOpenIddict_KeyTypeDefaultsToString(Type type)
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }

        [Theory]
        [InlineData(typeof(OpenIddictApplicationManager<OpenIddictApplication<Guid>>))]
        [InlineData(typeof(OpenIddictAuthorizationManager<OpenIddictAuthorization<Guid>>))]
        [InlineData(typeof(OpenIddictScopeManager<OpenIddictScope<Guid>>))]
        [InlineData(typeof(OpenIddictTokenManager<OpenIddictToken<Guid>>))]
        public void AddOpenIddict_KeyTypeCanBeOverriden(Type type)
        {
            // Arrange
            var services = new ServiceCollection();

            // Act
            services.AddOpenIddict<Guid>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }
    }
}
