/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace OpenIddict.Core.Tests;

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
        var exception = Assert.Throws<InvalidOperationException>(resolver.Get<OpenIddictScope>);

        Assert.Equal(SR.GetResourceString(SR.ID0230), exception.Message);
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
