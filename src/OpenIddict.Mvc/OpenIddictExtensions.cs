/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Mvc;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIddictExtensions
    {
        /// <summary>
        /// Registers the ASP.NET Core MVC model binders used by OpenIddict.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddMvcBinders([NotNull] this OpenIddictBuilder builder)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.Configure<MvcOptions>(options =>
            {
                // Skip the binder registration if it was already added to the providers collection.
                for (var index = 0; index < options.ModelBinderProviders.Count; index++)
                {
                    var provider = options.ModelBinderProviders[index];
                    if (provider is OpenIddictModelBinder)
                    {
                        return;
                    }
                }

                options.ModelBinderProviders.Insert(0, new OpenIddictModelBinder());
            });

            return builder;
        }
    }
}