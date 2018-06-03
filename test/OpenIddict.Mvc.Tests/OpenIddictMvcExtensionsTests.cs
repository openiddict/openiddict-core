/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Mvc.Tests
{
    public class OpenIddictMvcExtensionsTests
    {
        [Fact]
        public void UseMvc_RegistersModelBinderProvider()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseMvc();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<MvcOptions>>();

            // Assert
            Assert.Contains(options.Value.ModelBinderProviders, binder => binder is OpenIddictMvcBinderProvider);
        }
    }
}
