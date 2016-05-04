/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using OpenIddict;
using OpenIddict.Mvc;

namespace Microsoft.AspNetCore.Builder {
    public static class OpenIddictExtensions {
        /// <summary>
        /// Registers the MVC module, including the built-in
        /// authorization controller and the default consent views.
        /// </summary>
        /// <param name="builder">The services builder used by OpenIddict to register new services.</param>
        /// <returns>The <see cref="OpenIddictBuilder"/>.</returns>
        public static OpenIddictBuilder AddMvc([NotNull] this OpenIddictBuilder builder) {
            if (builder == null) {
                throw new ArgumentNullException(nameof(builder));
            }

            builder.Services.AddMvc();

            builder.Configure(options => {
                // Set ApplicationCanDisplayErrors to true to allow OpenIddictController 
                // to intercept the error responses returned by the OpenID Connect server.
                options.ApplicationCanDisplayErrors = true;

                if (!options.AuthorizationEndpointPath.HasValue) {
                    // Restore the default authorization endpoint path in the OpenIddict options.
                    options.AuthorizationEndpointPath = OpenIdConnectServerDefaults.AuthorizationEndpointPath;
                }

                if (!options.LogoutEndpointPath.HasValue) {
                    // Restore the default logout endpoint path in the OpenIddict options.
                    options.LogoutEndpointPath = OpenIdConnectServerDefaults.LogoutEndpointPath;
                }
            });

            // Run the MVC module in an isolated environment.
            return builder.AddModule("MVC", 10, app => app.Isolate(map => map.UseMvc(routes => {
                var options = app.ApplicationServices.GetRequiredService<IOptions<OpenIddictOptions>>().Value;

                // Register the actions corresponding to the authorization endpoint.
                if (options.AuthorizationEndpointPath.HasValue) {
                    routes.MapRoute("{D97891B4}", options.AuthorizationEndpointPath.Value.Substring(1), new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object, object, object>.Authorize)
                    });

                    routes.MapRoute("{7148DB83}", options.AuthorizationEndpointPath.Value.Substring(1) + "/accept", new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object, object, object>.Accept)
                    });

                    routes.MapRoute("{23438BCC}", options.AuthorizationEndpointPath.Value.Substring(1) + "/deny", new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object, object, object>.Deny)
                    });
                }

                // Register the action corresponding to the logout endpoint.
                if (options.LogoutEndpointPath.HasValue) {
                    routes.MapRoute("{C7DB102A}", options.LogoutEndpointPath.Value.Substring(1), new {
                        controller = "OpenIddict", action = nameof(OpenIddictController<object, object, object, object>.Logout)
                    });
                }
            }), services => {
                services.AddMvc()
                    // Note: ConfigureApplicationPartManager() must be
                    // called before AddControllersAsServices().
                    .ConfigureApplicationPartManager(manager => {
                        manager.ApplicationParts.Clear();
                        manager.ApplicationParts.Add(new OpenIddictPart(builder));
                    })

                    .AddControllersAsServices()

                    // Add an OpenIddict-specific convention to ensure that the generic
                    // OpenIddictController gets an appropriate controller name.
                    .AddMvcOptions(options => options.Conventions.Add(new OpenIddictConvention()))

                    .AddRazorOptions(options => {
                        // Update the Razor options to also use an embedded file provider that
                        // falls back to the current assembly when searching for views.
                        options.FileProviders.Add(new EmbeddedFileProvider(
                            assembly: typeof(OpenIddictController<,,,>).GetTypeInfo().Assembly,
                            baseNamespace: typeof(OpenIddictController<,,,>).Namespace));
                    });

                // Register the application manager in the isolated container.
                services.AddScoped(typeof(OpenIddictApplicationManager<>).MakeGenericType(builder.ApplicationType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null, "The parent DI container cannot be resolved from the HTTP context.");

                    // Resolve the application manager from the parent container.
                    return container.GetRequiredService(typeof(OpenIddictApplicationManager<>).MakeGenericType(builder.ApplicationType));
                });

                // Register the authorization manager in the isolated container.
                services.AddScoped(typeof(OpenIddictAuthorizationManager<>).MakeGenericType(builder.AuthorizationType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null, "The parent DI container cannot be resolved from the HTTP context.");

                    // Resolve the authorization manager from the parent container.
                    return container.GetRequiredService(typeof(OpenIddictAuthorizationManager<>).MakeGenericType(builder.AuthorizationType));
                });

                // Register the sign-in manager in the isolated container.
                services.AddScoped(typeof(SignInManager<>).MakeGenericType(builder.UserType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null, "The parent DI container cannot be resolved from the HTTP context.");

                    // Resolve the sign-in manager from the parent container.
                    return container.GetRequiredService(typeof(SignInManager<>).MakeGenericType(builder.UserType));
                });

                // Register the token manager in the isolated container.
                services.AddScoped(typeof(OpenIddictTokenManager<,>).MakeGenericType(
                    /* TToken: */ builder.TokenType,
                    /* TUser: */ builder.UserType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null, "The parent DI container cannot be resolved from the HTTP context.");

                    // Resolve the token manager from the parent container.
                    return container.GetRequiredService(typeof(OpenIddictTokenManager<,>).MakeGenericType(
                        /* TToken: */ builder.TokenType, /* TUser: */ builder.UserType));
                });

                // Register the user manager in the isolated container.
                services.AddScoped(typeof(UserManager<>).MakeGenericType(builder.UserType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null, "The parent DI container cannot be resolved from the HTTP context.");

                    // Resolve the user manager from the parent container.
                    return container.GetRequiredService(typeof(UserManager<>).MakeGenericType(builder.UserType));
                });

                // Register the options in the isolated container.
                services.AddSingleton(provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null, "The parent DI container cannot be resolved from the HTTP context.");

                    // Resolve the user manager from the parent container.
                    return container.GetRequiredService<IOptions<OpenIddictOptions>>();
                });
            }));
        }

        private class OpenIddictConvention : IControllerModelConvention {
            public void Apply(ControllerModel controller) {
                // Ensure the convention is only applied to the intended controller.
                Debug.Assert(controller.ControllerType != null);
                Debug.Assert(controller.ControllerType.IsGenericType);
                Debug.Assert(controller.ControllerType.GetGenericTypeDefinition() == typeof(OpenIddictController<,,,>));

                // Note: manually updating the controller name is required
                // to remove the ending markers added to the generic type name.
                controller.ControllerName = "OpenIddict";
            }
        }

        private class OpenIddictPart : ApplicationPart, IApplicationPartTypeProvider {
            public OpenIddictPart(OpenIddictBuilder builder) {
                Types = new[] {
                    typeof(OpenIddictController<,,,>).MakeGenericType(
                        /* TUser: */ builder.UserType,
                        /* TApplication: */ builder.ApplicationType,
                        /* TAuthorization: */ builder.AuthorizationType,
                        /* TToken: */ builder.TokenType).GetTypeInfo()
                };
            }

            public override string Name { get; } = "OpenIddict.Mvc";

            public IEnumerable<TypeInfo> Types { get; }
        }
    }
}