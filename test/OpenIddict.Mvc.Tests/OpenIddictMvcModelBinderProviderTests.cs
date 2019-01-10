/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Microsoft.AspNetCore.Mvc.ModelBinding.Metadata;
using Moq;
using Xunit;

namespace OpenIddict.Mvc.Tests
{
    public class OpenIddictMvcModelBinderProviderTests
    {
        [Theory]
        [InlineData(typeof(object))]
        [InlineData(typeof(IList<int>))]
        [InlineData(typeof(int[]))]
        public void GetBinder_ReturnsNullForUnsupportedTypes(Type type)
        {
            // Arrange
            var provider = new OpenIddictMvcBinderProvider();

            var metadata = new Mock<ModelMetadata>(ModelMetadataIdentity.ForType(type));

            var context = new Mock<ModelBinderProviderContext>();
            context.Setup(mock => mock.Metadata)
                .Returns(metadata.Object);

            // Act and assert
            Assert.Null(provider.GetBinder(context.Object));
        }

        [Theory]
        [InlineData(typeof(OpenIdConnectRequest))]
        [InlineData(typeof(OpenIdConnectResponse))]
        public void GetBinder_ReturnsNonNullForSupportedTypes(Type type)
        {
            // Arrange
            var provider = new OpenIddictMvcBinderProvider();

            var metadata = new Mock<ModelMetadata>(ModelMetadataIdentity.ForType(type));

            var context = new Mock<ModelBinderProviderContext>();
            context.Setup(mock => mock.Metadata)
                .Returns(metadata.Object);

            // Act and assert
            Assert.NotNull((BinderTypeModelBinder) provider.GetBinder(context.Object));
        }
    }
}
