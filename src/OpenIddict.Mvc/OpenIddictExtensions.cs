/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using Microsoft.AspNet.FileProviders;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Mvc.ApplicationModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Primitives;
using OpenIddict;

#if DNX451
using NWebsec.Owin;
#endif

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictBuilder UseMvc([NotNull] this OpenIddictBuilder builder) {
#if DNX451
            builder.AddModule(-20, app => app.UseKatana(owin => {
                // Insert a new middleware responsible of setting the Content-Security-Policy header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
                owin.UseCsp(options => options.DefaultSources(directive => directive.Self())
                                              .ImageSources(directive => directive.Self().CustomSources("*"))
                                              .ScriptSources(directive => directive.Self().UnsafeInline())
                                              .StyleSources(directive => directive.Self().UnsafeInline()));

                // Insert a new middleware responsible of setting the X-Content-Type-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXContentTypeOptions();

                // Insert a new middleware responsible of setting the X-Frame-Options header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXfo(options => options.Deny());

                // Insert a new middleware responsible of setting the X-Xss-Protection header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20security%20headers&referringTitle=NWebsec
                owin.UseXXssProtection(options => options.EnabledWithBlockMode());
            }));
#endif

            // Run the rest of the pipeline in an isolated environment.
            builder.AddModule(10, app => app.Isolate(map => map.UseMvc(routes => {
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
                var registration = builder.Builder.ApplicationServices.GetRequiredService<OpenIddictServices>();

                services.AddMvc()
                    // Register the OpenIddict controller.
                    .AddControllersAsServices(new[] {
                        typeof(OpenIddictController<,>).MakeGenericType(registration.UserType, registration.ApplicationType)
                    })

                    // Add an OpenIddict-specific convention to ensure that the generic
                    // OpenIddictController gets an appropriate controller name.
                    .AddMvcOptions(options => options.Conventions.Add(new OpenIddictConvention()))

                    .AddRazorOptions(options => {
                        // Update the Razor options to also use a combined provider that
                        // falls back to the current assembly when searching for views.
                        options.FileProvider = new CombinedFileSystemProvider(new[] {
                            options.FileProvider,
                            new EmbeddedFileProvider(
                                assembly: typeof(OpenIddictController<,>).GetTypeInfo().Assembly,
                                baseNamespace: "OpenIddict.Mvc")
                        });
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

                // Register the options in the isolated container.
                services.AddScoped(provider => builder.Options);
            }));

            return builder;
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

        private class CombinedFileSystemProvider : IFileProvider {
            public CombinedFileSystemProvider(IList<IFileProvider> providers) {
                Providers = providers;
            }

            public IList<IFileProvider> Providers { get; }

            public IDirectoryContents GetDirectoryContents(string subpath) {
                for (var index = 0; index < Providers.Count; index++) {
                    var provider = Providers[index];

                    var result = provider.GetDirectoryContents(subpath);
                    if (result != null && result.Exists) {
                        return result;
                    }
                }

                return new NotFoundDirectoryContents();
            }

            public IFileInfo GetFileInfo(string subpath) {
                for (var index = 0; index < Providers.Count; index++) {
                    var provider = Providers[index];

                    var result = provider.GetFileInfo(subpath);
                    if (result != null && result.Exists) {
                        return result;
                    }
                }

                return new NotFoundFileInfo(subpath);
            }

            public IChangeToken Watch(string filter) {
                for (var index = 0; index < Providers.Count; index++) {
                    var provider = Providers[index];

                    var result = provider.Watch(filter);
                    if (result != null) {
                        return result;
                    }
                }

                return NoopChangeToken.Singleton;
            }
        }
    }
}