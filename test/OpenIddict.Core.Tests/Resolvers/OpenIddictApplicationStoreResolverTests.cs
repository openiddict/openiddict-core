/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Core.Tests
{
    public class OpenIddictApplicationStoreResolverTests
    {
        [Fact]
        public void Get_ThrowsAnExceptionWhenStoreCannotBeFound()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictApplicationStoreResolver(provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<OpenIddictApplication>());

            Assert.Equal(SR.GetResourceString(SR.ID1227), exception.Message);
        }

        [Fact]
        public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedType()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictApplicationStore<OpenIddictApplication>>());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictApplicationStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<OpenIddictApplication>());
        }

        public class OpenIddictApplication { }
    }
}
