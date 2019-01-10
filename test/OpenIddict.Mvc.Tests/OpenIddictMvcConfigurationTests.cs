/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Metadata;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Mvc.Tests
{
    public class OpenIddictConfigurationExtensionsTests
    {
        [Fact]
        public void Configure_ThrowsAnExceptionForNullOptions()
        {
            // Arrange
            var configuration = new OpenIddictMvcConfiguration();

            // Act and assert
            var exception = Assert.Throws<ArgumentNullException>(() => configuration.Configure(null));

            Assert.Equal("options", exception.ParamName);
        }

        [Fact]
        public void Configure_RegistersModelBinderProvider()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseMvc();

            var options = services.BuildServiceProvider().GetRequiredService<IOptions<MvcOptions>>();

            // Assert
            Assert.Contains(options.Value.ModelBinderProviders, binder => binder is OpenIddictMvcBinderProvider);
        }

        [Fact]
        public void Configure_RegistersModelMetadataDetailsProviders()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictServerBuilder(services);

            // Act
            builder.UseMvc();

            var options = services.BuildServiceProvider().GetRequiredService<IOptions<MvcOptions>>();

            // Assert
            Assert.Contains(
                options.Value.ModelMetadataDetailsProviders.OfType<BindingSourceMetadataProvider>(),
                provider => provider.Type == typeof(OpenIdConnectRequest) &&
                            provider.BindingSource == BindingSource.Special);
            Assert.Contains(
                options.Value.ModelMetadataDetailsProviders.OfType<BindingSourceMetadataProvider>(),
                provider => provider.Type == typeof(OpenIdConnectResponse) &&
                            provider.BindingSource == BindingSource.Special);

            Assert.Contains(
                options.Value.ModelMetadataDetailsProviders.OfType<SuppressChildValidationMetadataProvider>(),
                provider => provider.Type == typeof(OpenIdConnectRequest));
            Assert.Contains(
                options.Value.ModelMetadataDetailsProviders.OfType<SuppressChildValidationMetadataProvider>(),
                provider => provider.Type == typeof(OpenIdConnectResponse));
        }
    }
}
