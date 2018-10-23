/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests
{
    public class OpenIddictEntityFrameworkCoreHelpersTests
    {
        [Fact]
        public void UseOpenIddict_RegistersDefaultEntityConfigurations()
        {
            // Arrange
            var builder = new ModelBuilder(new ConventionSet());

            // Act
            builder.UseOpenIddict();

            // Assert
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictApplication)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictAuthorization)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictScope)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictToken)));
        }

        [Fact]
        public void UseOpenIddict_RegistersDefaultEntityConfigurationsWithCustomKeyType()
        {
            // Arrange
            var builder = new ModelBuilder(new ConventionSet());

            // Act
            builder.UseOpenIddict<long>();

            // Assert
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictApplication<long>)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictAuthorization<long>)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictScope<long>)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(OpenIddictToken<long>)));
        }

        [Fact]
        public void UseOpenIddict_RegistersCustomEntityConfigurations()
        {
            // Arrange
            var builder = new ModelBuilder(new ConventionSet());

            // Act
            builder.UseOpenIddict<CustomApplication, CustomAuthorization, CustomScope, CustomToken, Guid>();

            // Assert
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomApplication)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomAuthorization)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomScope)));
            Assert.NotNull(builder.Model.FindEntityType(typeof(CustomToken)));
        }

        public class CustomApplication : OpenIddictApplication<Guid, CustomAuthorization, CustomToken> { }
        public class CustomAuthorization : OpenIddictAuthorization<Guid, CustomApplication, CustomToken> { }
        public class CustomScope : OpenIddictScope<Guid> { }
        public class CustomToken : OpenIddictToken<Guid, CustomApplication, CustomAuthorization> { }
    }
}
