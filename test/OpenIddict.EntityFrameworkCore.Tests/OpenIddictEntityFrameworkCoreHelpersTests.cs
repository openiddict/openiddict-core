/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using Moq;
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
            var builder = new Mock<ModelBuilder>(new ConventionSet());
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictApplication>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictAuthorization>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictScope>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictToken>>()))
                .Returns(builder.Object);

            // Act
            builder.Object.UseOpenIddict();

            // Assert
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictApplicationConfiguration<OpenIddictApplication, OpenIddictAuthorization, OpenIddictToken, string>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictAuthorizationConfiguration<OpenIddictAuthorization, OpenIddictApplication, OpenIddictToken, string>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictScopeConfiguration<OpenIddictScope, string>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictTokenConfiguration<OpenIddictToken, OpenIddictApplication, OpenIddictAuthorization, string>>()), Times.Once());
        }

        [Fact]
        public void UseOpenIddict_RegistersDefaultEntityConfigurationsWithCustomKeyType()
        {
            // Arrange
            var builder = new Mock<ModelBuilder>(new ConventionSet());
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictApplication<long>>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictAuthorization<long>>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictScope<long>>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictToken<long>>>()))
                .Returns(builder.Object);

            // Act
            builder.Object.UseOpenIddict<long>();

            // Assert
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictApplicationConfiguration<OpenIddictApplication<long>, OpenIddictAuthorization<long>, OpenIddictToken<long>, long>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictAuthorizationConfiguration<OpenIddictAuthorization<long>, OpenIddictApplication<long>, OpenIddictToken<long>, long>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictScopeConfiguration<OpenIddictScope<long>, long>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictTokenConfiguration<OpenIddictToken<long>, OpenIddictApplication<long>, OpenIddictAuthorization<long>, long>>()), Times.Once());
        }

        [Fact]
        public void UseOpenIddict_RegistersCustomEntityConfigurations()
        {
            // Arrange
            var builder = new Mock<ModelBuilder>(new ConventionSet());
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomApplication>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomAuthorization>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomScope>>()))
                .Returns(builder.Object);
            builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomToken>>()))
                .Returns(builder.Object);

            // Act
            builder.Object.UseOpenIddict<CustomApplication, CustomAuthorization, CustomScope, CustomToken, Guid>();

            // Assert
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictApplicationConfiguration<CustomApplication, CustomAuthorization, CustomToken, Guid>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictAuthorizationConfiguration<CustomAuthorization, CustomApplication, CustomToken, Guid>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictScopeConfiguration<CustomScope, Guid>>()), Times.Once());
            builder.Verify(mock => mock.ApplyConfiguration(
                It.IsAny<OpenIddictTokenConfiguration<CustomToken, CustomApplication, CustomAuthorization, Guid>>()), Times.Once());
        }

        public class CustomApplication : OpenIddictApplication<Guid, CustomAuthorization, CustomToken> { }
        public class CustomAuthorization : OpenIddictAuthorization<Guid, CustomApplication, CustomToken> { }
        public class CustomScope : OpenIddictScope<Guid> { }
        public class CustomToken : OpenIddictToken<Guid, CustomApplication, CustomAuthorization> { }
    }
}
