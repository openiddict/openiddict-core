/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Data.Entity;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFramework;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests
{
    public class OpenIddictExtensionsTests
    {
        [Theory]
        [InlineData(typeof(OpenIddictApplicationStoreResolver<DbContext>))]
        [InlineData(typeof(OpenIddictAuthorizationStoreResolver<DbContext>))]
        [InlineData(typeof(OpenIddictScopeStoreResolver<DbContext>))]
        [InlineData(typeof(OpenIddictTokenStoreResolver<DbContext>))]
        public void AddEntityFrameworkStores_RegistersEntityFrameworkStoreFactories(Type type)
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = services.AddOpenIddict().AddCore();

            // Act
            builder.AddEntityFrameworkStores<DbContext>();

            // Assert
            Assert.Contains(services, service => service.ImplementationType == type);
        }
    }
}
