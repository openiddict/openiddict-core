using System;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;

namespace OpenIddict.Mvc
{
    /// <summary>
    /// Represents an ASP.NET Core MVC model binder that is able to bind
    /// <see cref="OpenIdConnectRequest"/> and
    /// <see cref="OpenIdConnectResponse"/> instances.
    /// </summary>
    public class OpenIddictModelBinder : IModelBinder, IModelBinderProvider
    {
        /// <summary>
        /// Tries to bind a model from the request.
        /// </summary>
        /// <param name="context">The model binding context.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        public Task BindModelAsync([NotNull] ModelBindingContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.ModelType == typeof(OpenIdConnectRequest))
            {
                var request = context.HttpContext.GetOpenIdConnectRequest();
                if (request == null)
                {
                    throw new InvalidOperationException("The OpenID Connect request cannot be retrieved from the ASP.NET context. " +
                                                        "Make sure that 'app.UseOpenIddict()' is called before 'app.UseMvc()' and " +
                                                        "that the action route corresponds to the endpoint path registered via " +
                                                        "'services.AddOpenIddict().Enable[...]Endpoint(...)'.");
                }

                // Add a new validation state entry to prevent the built-in
                // model validators from validating the OpenID Connect request.
                context.ValidationState.Add(request, new ValidationStateEntry
                {
                    SuppressValidation = true
                });

                context.Result = ModelBindingResult.Success(request);

                return Task.FromResult(0);
            }

            else if (context.ModelType == typeof(OpenIdConnectResponse))
            {
                var response = context.HttpContext.GetOpenIdConnectResponse();
                if (response != null)
                {
                    // Add a new validation state entry to prevent the built-in
                    // model validators from validating the OpenID Connect response.
                    context.ValidationState.Add(response, new ValidationStateEntry
                    {
                        SuppressValidation = true
                    });
                }

                context.Result = ModelBindingResult.Success(response);

                return Task.FromResult(0);
            }

            throw new InvalidOperationException("The specified model type is not supported by this binder.");
        }

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
                return this;
            }

            return null;
        }
    }
}
