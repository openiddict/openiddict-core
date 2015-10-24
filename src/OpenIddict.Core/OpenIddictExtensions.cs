/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Reflection;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.FileProviders;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.StaticFiles;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using OpenIddict;

#if DNX451
using NWebsec.Owin;
#endif

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static OpenIddictServices AddOpenIddictCore<TApplication>([NotNull] this IdentityBuilder builder)
            where TApplication : class {
            builder.Services.AddAuthentication();
            builder.Services.AddCaching();

            builder.Services.AddSingleton(
                typeof(OpenIdConnectServerProvider),
                typeof(OpenIddictProvider<,>).MakeGenericType(
                    builder.UserType, typeof(TApplication)));

            builder.Services.AddScoped(
                typeof(OpenIddictManager<,>).MakeGenericType(
                    builder.UserType, typeof(TApplication)));

            var services = new OpenIddictServices(builder.Services) {
                ApplicationType = typeof(TApplication),
                RoleType = builder.RoleType,
                UserType = builder.UserType
            };

            builder.Services.AddInstance(services);

            return services;
        }

        public static IApplicationBuilder UseOpenIddict([NotNull] this IApplicationBuilder app) {
            return app.UseOpenIddict(options => { });
        }

        public static IApplicationBuilder UseOpenIddict(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIddictBuilder> configuration) {
            var builder = new OpenIddictBuilder(app);

            // By default, enable AllowInsecureHttp in development/testing environments.
            var environment = app.ApplicationServices.GetRequiredService<IHostingEnvironment>();
            builder.Options.AllowInsecureHttp = environment.IsDevelopment() || environment.IsEnvironment("Testing");

            configuration(builder);

            if (!builder.Options.UseCustomViews) {
                app.UseStaticFiles(new StaticFileOptions {
                    FileProvider = new EmbeddedFileProvider(
                        assembly: Assembly.Load(new AssemblyName("OpenIddict.Assets")),
                        baseNamespace: "OpenIddict.Assets")
                });
            }

            app.UseCors(options => {
                options.AllowAnyHeader();
                options.AllowAnyMethod();
                options.AllowAnyOrigin();
                options.AllowCredentials();
            });

            // Add OpenIdConnectServerMiddleware to the ASP.NET 5 pipeline.
            app.UseOpenIdConnectServer(options => {
                options.Options = builder.Options;
                options.Provider = app.ApplicationServices.GetRequiredService<OpenIdConnectServerProvider>();
            });

#if DNX451
            app.UseKatana(owin => {
                // Insert a new middleware responsible of setting the Content-Security-Policy header.
                // See https://nwebsec.codeplex.com/wikipage?title=Configuring%20Content%20Security%20Policy&referringTitle=NWebsec
                owin.UseCsp(options => options.DefaultSources(directive => directive.Self())
                                              .ImageSources(directive => directive.Self().CustomSources("*"))
                                              .ScriptSources(directive => directive.UnsafeInline())
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
            });
#endif

            // Run the rest of the pipeline in an isolated environment.
            return app.Isolate(container => container.UseMvc(routes => {
                // Register the actions corresponding to the authorization endpoint.
                if (builder.Options.AuthorizationEndpointPath.HasValue) {
                    routes.MapRoute("{D97891B4}", builder.Options.AuthorizationEndpointPath.Value.Substring(1), new {
                        controller = typeof(OpenIddictController<,>).Name,
                        action = nameof(OpenIddictController<dynamic, dynamic>.Authorize)
                    });

                    routes.MapRoute("{7148DB83}", builder.Options.AuthorizationEndpointPath.Value.Substring(1) + "/accept", new {
                        controller = typeof(OpenIddictController<,>).Name,
                        action = nameof(OpenIddictController<dynamic, dynamic>.Accept)
                    });

                    routes.MapRoute("{23438BCC}", builder.Options.AuthorizationEndpointPath.Value.Substring(1) + "/deny", new {
                        controller = typeof(OpenIddictController<,>).Name,
                        action = nameof(OpenIddictController<dynamic, dynamic>.Deny)
                    });
                }

                // Register the action corresponding to the logout endpoint.
                if (builder.Options.LogoutEndpointPath.HasValue) {
                    routes.MapRoute("{C7DB102A}", builder.Options.LogoutEndpointPath.Value.Substring(1), new {
                        controller = typeof(OpenIddictController<,>).Name,
                        action = nameof(OpenIddictController<dynamic, dynamic>.Logout)
                    });
                }
            }), services => {
                var instance = app.ApplicationServices.GetRequiredService<OpenIddictServices>();

                services.AddMvc()
                    // Register the OpenIddict controller.
                    .AddControllersAsServices(new[] {
                        typeof(OpenIddictController<,>).MakeGenericType(instance.UserType, instance.ApplicationType)
                    })

                    // Update the Razor options to use an embedded provider
                    // extracting its views from the current assembly.
                    .AddRazorOptions(options => {
                        if (!builder.Options.UseCustomViews) {
                            options.FileProvider = new EmbeddedFileProvider(
                                assembly: typeof(OpenIddictOptions).GetTypeInfo().Assembly,
                                baseNamespace: "OpenIddict.Core");
                        }
                    });

                // Register the sign-in manager in the isolated container.
                services.AddScoped(typeof(SignInManager<>).MakeGenericType(instance.UserType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null);

                    // Resolve the sign-in manager from the parent container.
                    return container.GetRequiredService(typeof(SignInManager<>).MakeGenericType(instance.UserType));
                });

                // Register the user manager in the isolated container.
                services.AddScoped(typeof(OpenIddictManager<,>).MakeGenericType(instance.UserType, instance.ApplicationType), provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null);

                    // Resolve the user manager from the parent container.
                    return container.GetRequiredService(typeof(OpenIddictManager<,>).MakeGenericType(instance.UserType, instance.ApplicationType));
                });

                services.AddScoped(provider => builder.Options);
            });
        }
    }
}