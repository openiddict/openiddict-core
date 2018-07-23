/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using OpenIddict.Abstractions;
using Xunit;

namespace OpenIddict.Core.Tests
{
    public class OpenIddictScopeStoreResolverTests
    {
        [Fact]
        public void Get_ThrowsAnExceptionWhenStoreCannotBeFound()
        {
            // Arrange
            var services = new ServiceCollection();
            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictScopeStoreResolver(provider);

            // Act and assert
            var exception = Assert.Throws<InvalidOperationException>(() => resolver.Get<OpenIddictScope>());

            Assert.Equal(new StringBuilder()
                .AppendLine("No scope store has been registered in the dependency injection container.")
                .Append("To register the Entity Framework Core stores, reference the 'OpenIddict.EntityFrameworkCore' ")
                .AppendLine("package and call 'services.AddOpenIddict().AddCore().UseEntityFrameworkCore()'.")
                .Append("To register a custom store, create an implementation of 'IOpenIddictScopeStore' and ")
                .Append("use 'services.AddOpenIddict().AddCore().AddScopeStore()' to add it to the DI container.")
                .ToString(), exception.Message);
        }

        [Fact]
        public void Get_ReturnsCustomStoreCorrespondingToTheSpecifiedType()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddSingleton(Mock.Of<IOpenIddictScopeStore<OpenIddictScope>>());

            var provider = services.BuildServiceProvider();
            var resolver = new OpenIddictScopeStoreResolver(provider);

            // Act and assert
            Assert.NotNull(resolver.Get<OpenIddictScope>());
        }

        public class OpenIddictScope { }
    }
}
