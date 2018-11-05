/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;

namespace OpenIddict.Mvc
{
    /// <summary>
    /// Represents an ASP.NET Core MVC model binder provider that is able to provide instances
    /// of <see cref="OpenIddictMvcBinder"/> for the OpenID Connect server primitives.
    /// </summary>
    public class OpenIddictMvcBinderProvider : IModelBinderProvider
    {
        /// <summary>
        /// Tries to resolve the model binder corresponding to the given model.
        /// </summary>
        /// <param name="context">The model binding context.</param>
        /// <returns>The current instance or <c>null</c> if the model is not supported.</returns>
        public IModelBinder GetBinder([NotNull] ModelBinderProviderContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Metadata.ModelType == typeof(OpenIdConnectRequest) ||
                context.Metadata.ModelType == typeof(OpenIdConnectResponse))
            {
                return new BinderTypeModelBinder(typeof(OpenIddictMvcBinder));
            }

            return null;
        }
    }
}
