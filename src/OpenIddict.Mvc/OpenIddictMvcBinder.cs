/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenIddict.Mvc
{
    /// <summary>
    /// Represents an ASP.NET Core MVC model binder that is able to bind
    /// <see cref="OpenIdConnectRequest"/> and <see cref="OpenIdConnectResponse"/> instances.
    /// </summary>
    public class OpenIddictMvcBinder : IModelBinder
    {
        private readonly IOptionsMonitor<OpenIddictMvcOptions> _options;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIddictMvcBinder"/> class.
        /// <see cref="OpenIdConnectRequest"/> and <see cref="OpenIdConnectResponse"/> instances.
        /// </summary>
        public OpenIddictMvcBinder([NotNull] IOptionsMonitor<OpenIddictMvcOptions> options)
            => _options = options;

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
                if (request == null && !_options.CurrentValue.DisableBindingExceptions)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The OpenID Connect request cannot be retrieved from the ASP.NET context.")
                        .Append("Make sure that 'app.UseAuthentication()' is called before 'app.UseMvc()' ")
                        .Append("and that the action route corresponds to the endpoint path registered via ")
                        .Append("'services.AddOpenIddict().AddServer().Enable[...]Endpoint(...)'.")
                        .ToString());
                }

                if (request != null)
                {
                    // Add a new validation state entry to prevent the built-in
                    // model validators from validating the OpenID Connect request.
                    context.ValidationState.Add(request, new ValidationStateEntry
                    {
                        SuppressValidation = true
                    });
                }

                context.BindingSource = BindingSource.Special;
                context.Result = ModelBindingResult.Success(request);

                return Task.CompletedTask;
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

                context.BindingSource = BindingSource.Special;
                context.Result = ModelBindingResult.Success(response);

                return Task.CompletedTask;
            }

            throw new InvalidOperationException("The specified model type is not supported by this binder.");
        }
    }
}
