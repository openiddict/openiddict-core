/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Conventions;
using Moq;
using OpenIddict.EntityFrameworkCore.Models;
using Xunit;

namespace OpenIddict.EntityFrameworkCore.Tests;

public class OpenIddictEntityFrameworkCoreHelpersTests
{
    [Fact]
    public void UseOpenIddict_RegistersDefaultEntityConfigurations()
    {
        // Arrange
        var builder = new Mock<ModelBuilder>(new ConventionSet());
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreApplication>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreAuthorization>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreResource>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreScope>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreSession>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreToken>>()))
            .Returns(builder.Object);

        // Act
        builder.Object.UseOpenIddict();

        // Assert
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreApplicationConfiguration<OpenIddictEntityFrameworkCoreApplication, OpenIddictEntityFrameworkCoreAuthorization, OpenIddictEntityFrameworkCoreToken, string>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreAuthorizationConfiguration<OpenIddictEntityFrameworkCoreAuthorization, OpenIddictEntityFrameworkCoreApplication, OpenIddictEntityFrameworkCoreToken, string>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreResourceConfiguration<OpenIddictEntityFrameworkCoreResource, string>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreScopeConfiguration<OpenIddictEntityFrameworkCoreScope, string>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreSessionConfiguration<OpenIddictEntityFrameworkCoreSession, OpenIddictEntityFrameworkCoreApplication, OpenIddictEntityFrameworkCoreAuthorization, OpenIddictEntityFrameworkCoreToken, string>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreTokenConfiguration<OpenIddictEntityFrameworkCoreToken, OpenIddictEntityFrameworkCoreApplication, OpenIddictEntityFrameworkCoreAuthorization, string>>()), Times.Once());
    }

    [Fact]
    public void UseOpenIddict_RegistersDefaultEntityConfigurationsWithCustomKeyType()
    {
        // Arrange
        var builder = new Mock<ModelBuilder>(new ConventionSet());
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreApplication<long>>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreAuthorization<long>>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreResource<long>>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreScope<long>>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreSession<long>>>() ))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<OpenIddictEntityFrameworkCoreToken<long>>>()))
            .Returns(builder.Object);

        // Act
        builder.Object.UseOpenIddict<long>();

        // Assert
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreApplicationConfiguration<OpenIddictEntityFrameworkCoreApplication<long>, OpenIddictEntityFrameworkCoreAuthorization<long>, OpenIddictEntityFrameworkCoreToken<long>, long>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreAuthorizationConfiguration<OpenIddictEntityFrameworkCoreAuthorization<long>, OpenIddictEntityFrameworkCoreApplication<long>, OpenIddictEntityFrameworkCoreToken<long>, long>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreResourceConfiguration<OpenIddictEntityFrameworkCoreResource<long>, long>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreScopeConfiguration<OpenIddictEntityFrameworkCoreScope<long>, long>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreSessionConfiguration<OpenIddictEntityFrameworkCoreSession<long>, OpenIddictEntityFrameworkCoreApplication<long>, OpenIddictEntityFrameworkCoreAuthorization<long>, OpenIddictEntityFrameworkCoreToken<long>, long>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreTokenConfiguration<OpenIddictEntityFrameworkCoreToken<long>, OpenIddictEntityFrameworkCoreApplication<long>, OpenIddictEntityFrameworkCoreAuthorization<long>, long>>()), Times.Once());
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
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomResource>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomScope>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomSession>>()))
            .Returns(builder.Object);
        builder.Setup(mock => mock.ApplyConfiguration(It.IsAny<IEntityTypeConfiguration<CustomToken>>()))
            .Returns(builder.Object);

        // Act
        builder.Object.UseOpenIddict<CustomApplication, CustomAuthorization, CustomResource, CustomScope, CustomSession, CustomToken, Guid>();

        // Assert
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreApplicationConfiguration<CustomApplication, CustomAuthorization, CustomToken, Guid>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreAuthorizationConfiguration<CustomAuthorization, CustomApplication, CustomToken, Guid>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreResourceConfiguration<CustomResource, Guid>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreScopeConfiguration<CustomScope, Guid>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreSessionConfiguration<CustomSession, CustomApplication, CustomAuthorization, CustomToken, Guid>>()), Times.Once());
        builder.Verify(mock => mock.ApplyConfiguration(
            It.IsAny<OpenIddictEntityFrameworkCoreTokenConfiguration<CustomToken, CustomApplication, CustomAuthorization, Guid>>()), Times.Once());
    }

    public class CustomApplication : OpenIddictEntityFrameworkCoreApplication<Guid, CustomAuthorization, CustomToken>;
    public class CustomAuthorization : OpenIddictEntityFrameworkCoreAuthorization<Guid, CustomApplication, CustomToken>;
    public class CustomResource : OpenIddictEntityFrameworkCoreResource<Guid>;
    public class CustomScope : OpenIddictEntityFrameworkCoreScope<Guid>;
    public class CustomSession : OpenIddictEntityFrameworkCoreSession<Guid, CustomApplication, CustomAuthorization>;
    public class CustomToken : OpenIddictEntityFrameworkCoreToken<Guid, CustomApplication, CustomAuthorization>;
}
