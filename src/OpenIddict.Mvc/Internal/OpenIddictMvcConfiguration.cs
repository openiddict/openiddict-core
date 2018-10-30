/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Options;

namespace OpenIddict.Mvc.Internal
{
    /// <summary>
    /// Contains the methods required to ensure that the OpenIddict MVC configuration is valid.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    public class OpenIddictMvcConfiguration : IConfigureOptions<MvcOptions>
    {
        /// <summary>
        /// Registers the OpenIddict MVC components in the MVC options.
        /// </summary>
        /// <param name="options">The options instance to initialize.</param>
        public void Configure([NotNull] MvcOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            options.ModelBinderProviders.Insert(0, new OpenIddictMvcBinderProvider());
            options.ModelMetadataDetailsProviders.Add(new SuppressChildValidationMetadataProvider(typeof(OpenIdConnectRequest)));
            options.ModelMetadataDetailsProviders.Add(new SuppressChildValidationMetadataProvider(typeof(OpenIdConnectResponse)));
        }
    }
}
