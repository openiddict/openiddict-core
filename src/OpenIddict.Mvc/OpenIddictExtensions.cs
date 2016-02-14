/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Reflection;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using OpenIddict;
using OpenIddict.Mvc;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictBuilder UseMvc([NotNull] this OpenIddictBuilder builder) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            // Run MVC in an isolated environment.
            return builder.AddModule("MVC", 10, app => app.Isolate(map => map.UseMvc(routes => {
                // Register the actions corresponding to the authorization endpoint.
                if (builder.Options.AuthorizationEndpointPath.HasValue) {
                    routes.MapRoute("{D97891B4}", builder.Options.AuthorizationEndpointPath.Value.Substring(1), new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object>.Authorize)
                    });

                    routes.MapRoute("{7148DB83}", builder.Options.AuthorizationEndpointPath.Value.Substring(1) + "/accept", new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object>.Accept)
                    });

                    routes.MapRoute("{23438BCC}", builder.Options.AuthorizationEndpointPath.Value.Substring(1) + "/deny", new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object>.Deny)
                    });
                }

                // Register the action corresponding to the logout endpoint.
                if (builder.Options.LogoutEndpointPath.HasValue) {
                    routes.MapRoute("{C7DB102A}", builder.Options.LogoutEndpointPath.Value.Substring(1), new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object>.Logout)
                    });
                }
            }), services => {
                var registration = app.ApplicationServices.GetRequiredService<OpenIddictServices>();

                services.AddMvc()
                    // Register the OpenIddict controller.
                    .AddControllersAsServices(new[] {
                        typeof(OpenIddictController<,>).MakeGenericType(registration.UserType, registration.ApplicationType)
                    })

                    // Add an OpenIddict-specific convention to ensure that the generic
                    // OpenIddictController gets an appropriate controller name.
                    .AddMvcOptions(options => options.Conventions.Add(new OpenIddictConvention()))

                    .AddRazorOptions(options => {
                        // Update the Razor options to also use an embedded file provider that
                        // falls back to the current assembly when searching for views.
                        options.FileProviders.Add(new EmbeddedFileProvider(
                            assembly: typeof(OpenIddictController<,>).GetTypeInfo().Assembly,
                            baseNamespace: typeof(OpenIddictController<,>).Namespace));
                    });

                // Register the sign-in manager in the isolated container.
                services.AddScoped(typeof(SignInManager<>).MakeGenericType(registration.UserType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null);

                    // Resolve the sign-in manager from the parent container.
                    return container.GetRequiredService(typeof(SignInManager<>).MakeGenericType(registration.UserType));
                });

                // Register the user manager in the isolated container.
                services.AddScoped(typeof(OpenIddictManager<,>).MakeGenericType(registration.UserType, registration.ApplicationType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null);

                    // Resolve the user manager from the parent container.
                    return container.GetRequiredService(typeof(OpenIddictManager<,>).MakeGenericType(registration.UserType, registration.ApplicationType));
                });

                // Register the user manager in the isolated container.
                services.AddScoped(typeof(UserManager<>).MakeGenericType(registration.UserType), provider => {
                    return provider.GetRequiredService(typeof(OpenIddictManager<,>)
                        .MakeGenericType(registration.UserType, registration.ApplicationType));
                });

                // Register the options in the isolated container.
                services.AddScoped(provider => builder.Options);
            }));
        }

        private class OpenIddictConvention : IControllerModelConvention {
            public void Apply(ControllerModel controller) {
                // Ensure the convention is only applied to the intended controller.
                Debug.Assert(controller.ControllerType != null);
                Debug.Assert(controller.ControllerType.IsGenericType);
                Debug.Assert(controller.ControllerType.GetGenericTypeDefinition() == typeof(OpenIddictController<,>));

                // Note: manually updating the controller name is required
                // to remove the ending markers added to the generic type name.
                controller.ControllerName = "OpenIddict";
            }
        }
    }
}