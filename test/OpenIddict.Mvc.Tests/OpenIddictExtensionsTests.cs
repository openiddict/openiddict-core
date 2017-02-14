using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace OpenIddict.Mvc.Tests
{
    public class OpenIddictExtensionsTests
    {
        [Fact]
        public void AddMvcBinders_RegistersModelBinderProvider()
        {
            // Arrange
            var services = new ServiceCollection();
            services.AddOptions();

            var builder = new OpenIddictBuilder(services);

            // Act
            builder.AddMvcBinders();

            var provider = services.BuildServiceProvider();
            var options = provider.GetRequiredService<IOptions<MvcOptions>>();

            // Assert
            Assert.Contains(options.Value.ModelBinderProviders, binder => binder is OpenIddictModelBinder);
        }
    }
}
