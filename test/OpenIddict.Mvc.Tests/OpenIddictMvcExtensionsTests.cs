/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Mvc.Tests
{
    public class OpenIddictMvcExtensionsTests
    {
        [Fact]
        public void UseMvc_ThrowsAnExceptionForNullBuilder()
        {
            // Arrange
            var builder = (OpenIddictServerBuilder) null;

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseMvc());

            Assert.Equal("builder", exception.ParamName);
        }

        [Fact]
        public void UseMvc_ThrowsAnExceptionForNullConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            var builder = new OpenIddictServerBuilder(services);

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => builder.UseMvc(configuration: null));

            Assert.Equal("configuration", exception.ParamName);
        }

        [Fact]
        public void UseMvc_RegistersConfiguration()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseMvc();

            // Assert
            Assert.Contains(services, service => service.ServiceType == typeof(IConfigureOptions<MvcOptions>) &&
                                                 service.ImplementationType == typeof(OpenIddictMvcConfiguration));
        }
    }
}
