/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace OpenIddict.Mvc.Tests
{
    public class OpenIddictMvcModelBinderTests
    {
        [Theory]
        [InlineData(typeof(object))]
        [InlineData(typeof(IList<int>))]
        [InlineData(typeof(int[]))]
        public async Task BindModelAsync_ThrowsAnExceptionForUnsupportedTypes(Type type)
        {
            // Arrange
            var options = Mock.Of<IOptionsMonitor<OpenIddictMvcOptions>>(
                mock => mock.CurrentValue == new OpenIddictMvcOptions());

            var binder = new OpenIddictMvcBinder(options);
            var provider = new EmptyModelMetadataProvider();

            var context = new DefaultModelBindingContext
            {
                ModelMetadata = provider.GetMetadataForType(type)
            };

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return binder.BindModelAsync(context);
            });

            Assert.Equal("The specified model type is not supported by this binder.", exception.Message);
        }

        [Fact]
        public async Task BindModelAsync_ThrowsAnExceptionWhenRequestCannotBeFound()
        {
            // Arrange
            var options = Mock.Of<IOptionsMonitor<OpenIddictMvcOptions>>(
                mock => mock.CurrentValue == new OpenIddictMvcOptions());

            var binder = new OpenIddictMvcBinder(options);
            var provider = new EmptyModelMetadataProvider();

            var context = new DefaultModelBindingContext
            {
                ActionContext = new ActionContext()
                {
                    HttpContext = new DefaultHttpContext(),
                },

                ModelMetadata = provider.GetMetadataForType(typeof(OpenIdConnectRequest))
            };

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return binder.BindModelAsync(context);
            });

            Assert.Equal(new StringBuilder()
                .AppendLine("The OpenID Connect request cannot be retrieved from the ASP.NET context.")
                .Append("Make sure that 'app.UseAuthentication()' is called before 'app.UseMvc()' ")
                .Append("and that the action route corresponds to the endpoint path registered via ")
                .Append("'services.AddOpenIddict().AddServer().Enable[...]Endpoint(...)'.")
                .ToString(), exception.Message);
        }

        [Fact]
        public async Task BindModelAsync_ReturnsNullWhenRequestCannotBeFoundAndExceptionsAreDisabled()
        {
            // Arrange
            var options = Mock.Of<IOptionsMonitor<OpenIddictMvcOptions>>(
                mock => mock.CurrentValue == new OpenIddictMvcOptions
                {
                    DisableBindingExceptions = true
                });

            var binder = new OpenIddictMvcBinder(options);
            var provider = new EmptyModelMetadataProvider();

            var context = new DefaultModelBindingContext
            {
                ActionContext = new ActionContext()
                {
                    HttpContext = new DefaultHttpContext(),
                },

                ModelMetadata = provider.GetMetadataForType(typeof(OpenIdConnectRequest))
            };

            // Act
            await binder.BindModelAsync(context);

            // Assert
            Assert.True(context.Result.IsModelSet);
            Assert.Null(context.Result.Model);
            Assert.Equal(BindingSource.Special, context.BindingSource);
        }

        [Fact]
        public async Task BindModelAsync_ReturnsNullWhenResponseCannotBeFound()
        {
            // Arrange
            var options = Mock.Of<IOptionsMonitor<OpenIddictMvcOptions>>(
                mock => mock.CurrentValue == new OpenIddictMvcOptions());

            var binder = new OpenIddictMvcBinder(options);
            var provider = new EmptyModelMetadataProvider();

            var context = new DefaultModelBindingContext
            {
                ActionContext = new ActionContext()
                {
                    HttpContext = new DefaultHttpContext(),
                },

                ModelMetadata = provider.GetMetadataForType(typeof(OpenIdConnectResponse)),

                ValidationState = new ValidationStateDictionary()
            };

            // Act
            await binder.BindModelAsync(context);

            // Assert
            Assert.True(context.Result.IsModelSet);
            Assert.Null(context.Result.Model);
            Assert.Equal(BindingSource.Special, context.BindingSource);
        }

        [Fact]
        public async Task BindModelAsync_ReturnsAmbientRequest()
        {
            // Arrange
            var options = Mock.Of<IOptionsMonitor<OpenIddictMvcOptions>>(
                mock => mock.CurrentValue == new OpenIddictMvcOptions());

            var binder = new OpenIddictMvcBinder(options);
            var provider = new EmptyModelMetadataProvider();

            var request = new OpenIdConnectRequest();

            var features = new FeatureCollection();
            features.Set(new OpenIdConnectServerFeature
            {
                Request = request
            });

            var context = new DefaultModelBindingContext
            {
                ActionContext = new ActionContext()
                {
                    HttpContext = new DefaultHttpContext(features),
                },

                ModelMetadata = provider.GetMetadataForType(typeof(OpenIdConnectRequest)),

                ValidationState = new ValidationStateDictionary()
            };

            // Act
            await binder.BindModelAsync(context);

            // Assert
            Assert.True(context.Result.IsModelSet);
            Assert.Same(request, context.Result.Model);
            Assert.True(context.ValidationState[request].SuppressValidation);
            Assert.Equal(BindingSource.Special, context.BindingSource);
        }

        [Fact]
        public async Task BindModelAsync_ReturnsAmbientResponse()
        {
            // Arrange
            var options = Mock.Of<IOptionsMonitor<OpenIddictMvcOptions>>(
                mock => mock.CurrentValue == new OpenIddictMvcOptions());

            var binder = new OpenIddictMvcBinder(options);
            var provider = new EmptyModelMetadataProvider();

            var response = new OpenIdConnectResponse();

            var features = new FeatureCollection();
            features.Set(new OpenIdConnectServerFeature
            {
                Response = response
            });

            var context = new DefaultModelBindingContext
            {
                ActionContext = new ActionContext()
                {
                    HttpContext = new DefaultHttpContext(features),
                },

                ModelMetadata = provider.GetMetadataForType(typeof(OpenIdConnectResponse)),

                ValidationState = new ValidationStateDictionary()
            };

            // Act
            await binder.BindModelAsync(context);

            // Assert
            Assert.True(context.Result.IsModelSet);
            Assert.Same(response, context.Result.Model);
            Assert.True(context.ValidationState[response].SuppressValidation);
            Assert.Equal(BindingSource.Special, context.BindingSource);
        }
    }
}
