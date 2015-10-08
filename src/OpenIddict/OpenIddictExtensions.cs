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
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.StaticFiles;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using OpenIddict;

#if DNX451
using NWebsec.Owin;
#endif

namespace Microsoft.AspNet.Builder {
    public static class OpenIddictExtensions {
        public static IApplicationBuilder UseOpenIddict<TContext>([NotNull] this IApplicationBuilder app)
            where TContext : OpenIddictContext<IdentityUser, IdentityRole, string> {
            return app.UseOpenIddict<TContext>(configuration => { });
        }

        public static IApplicationBuilder UseOpenIddict<TContext>(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIddictOptions> configuration)
            where TContext : OpenIddictContext<IdentityUser, IdentityRole, string> {
            return app.UseOpenIddict<TContext, IdentityUser>(configuration);
        }

        public static IApplicationBuilder UseOpenIddict<TContext, TUser>([NotNull] this IApplicationBuilder app)
            where TContext : OpenIddictContext<TUser, IdentityRole, string>
            where TUser : IdentityUser<string> {
            return app.UseOpenIddict<TContext, TUser>(configuration => { });
        }

        public static IApplicationBuilder UseOpenIddict<TContext, TUser>(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIddictOptions> configuration)
            where TContext : OpenIddictContext<TUser, IdentityRole, string>
            where TUser : IdentityUser<string> {
            return app.UseOpenIddict<TContext, TUser, IdentityRole>(configuration);
        }

        public static IApplicationBuilder UseOpenIddict<TContext, TUser, TRole>([NotNull] this IApplicationBuilder app)
            where TContext : OpenIddictContext<TUser, TRole, string>
            where TRole : IdentityRole<string>
            where TUser : IdentityUser<string> {
            return app.UseOpenIddict<TContext, TUser, TRole>(configuration => { });
        }

        public static IApplicationBuilder UseOpenIddict<TContext, TUser, TRole>(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIddictOptions> configuration)
            where TContext : OpenIddictContext<TUser, TRole, string>
            where TRole : IdentityRole<string>
            where TUser : IdentityUser<string> {
            return app.UseOpenIddict<TContext, TUser, TRole, string>(configuration);
        }

        public static IApplicationBuilder UseOpenIddict<TContext, TUser, TRole, TKey>(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIddictOptions> configuration)
            where TContext : OpenIddictContext<TUser, TRole, TKey>
            where TUser : IdentityUser<TKey>
            where TRole : IdentityRole<TKey>
            where TKey : IEquatable<TKey> {
            var instance = new OpenIddictOptions();

            // Turn ApplicationCanDisplayErrors on to ensure ASP.NET MVC 6
            // handles errored requests and returns an appropriate error page.
            instance.ApplicationCanDisplayErrors = true;

            // Call the configuration delegate defined by the user.
            configuration(instance);

            // Run OpenIddict in an isolated environment.
            return app.Isolate(builder => {
                // Add the options to the ASP.NET context
                // before executing the rest of the pipeline.
                builder.Use(next => context => {
                    context.Items[typeof(OpenIddictOptions)] = instance;

                    return next(context);
                });

#if DNX451
                builder.UseKatana(owin => {
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

                builder.UseStaticFiles(new StaticFileOptions {
                    FileProvider = new EmbeddedFileProvider(
                        assembly: Assembly.Load(new AssemblyName("OpenIddict.Assets")),
                        baseNamespace: "OpenIddict.Assets")
                });

                builder.UseCors(options => {
                    options.AllowAnyHeader();
                    options.AllowAnyMethod();
                    options.AllowAnyOrigin();
                    options.AllowCredentials();
                });

                // Add OpenIdConnectServerMiddleware to the ASP.NET 5 pipeline.
                builder.UseOpenIdConnectServer(options => {
                    options.Provider = new OpenIddictProvider<TContext, TUser, TRole, TKey>();

                    // Copy the OpenIddict options to the ASOS configuration.
                    options.Options.AuthenticationScheme = instance.AuthenticationScheme;

                    options.Options.Issuer = instance.Issuer;

                    options.Options.AuthorizationEndpointPath = instance.AuthorizationEndpointPath;
                    options.Options.LogoutEndpointPath = instance.LogoutEndpointPath;

                    options.Options.AccessTokenLifetime = instance.AccessTokenLifetime;
                    options.Options.AuthorizationCodeLifetime = instance.AuthorizationCodeLifetime;
                    options.Options.IdentityTokenLifetime = instance.IdentityTokenLifetime;
                    options.Options.RefreshTokenLifetime = instance.RefreshTokenLifetime;

                    options.Options.ApplicationCanDisplayErrors = instance.ApplicationCanDisplayErrors;
                    options.Options.AllowInsecureHttp = instance.AllowInsecureHttp;
                });

                // Register ASP.NET MVC 6 and the actions
                // associated to the OpenIddict controller.
                builder.UseMvc(routes => {
                    // Register the actions corresponding to the authorization endpoint.
                    if (instance.AuthorizationEndpointPath.HasValue) {
                        routes.MapRoute("{D97891B4}", instance.AuthorizationEndpointPath.Value.Substring(1), new {
                            controller = typeof(OpenIddictController<TContext, TUser, TRole, TKey>).Name,
                            action = nameof(OpenIddictController<TContext, TUser, TRole, TKey>.Authorize)
                        });

                        routes.MapRoute("{7148DB83}", instance.AuthorizationEndpointPath.Value.Substring(1) + "/accept", new {
                            controller = typeof(OpenIddictController<TContext, TUser, TRole, TKey>).Name,
                            action = nameof(OpenIddictController<TContext, TUser, TRole, TKey>.Accept)
                        });

                        routes.MapRoute("{23438BCC}", instance.AuthorizationEndpointPath.Value.Substring(1) + "/deny", new {
                            controller = typeof(OpenIddictController<TContext, TUser, TRole, TKey>).Name,
                            action = nameof(OpenIddictController<TContext, TUser, TRole, TKey>.Deny)
                        });
                    }

                    // Register the action corresponding to the logout endpoint.
                    if (instance.LogoutEndpointPath.HasValue) {
                        routes.MapRoute("{C7DB102A}", instance.LogoutEndpointPath.Value.Substring(1), new {
                            controller = typeof(OpenIddictController<TContext, TUser, TRole, TKey>).Name,
                            action = nameof(OpenIddictController<TContext, TUser, TRole, TKey>.Logout)
                        });
                    }
                });
            }, services => {
                services.AddAuthentication();
                services.AddCaching();
                services.AddCors();
                services.AddOptions();

                services.AddMvc()
                    // Register the OpenIddict controller.
                    .AddControllersAsServices(new[] {
                        typeof(OpenIddictController<TContext, TUser, TRole, TKey>)
                    })

                    // Update the Razor options to use an embedded provider
                    // extracting its views from the current assembly.
                    .AddRazorOptions(options => {
                        options.FileProvider = new EmbeddedFileProvider(
                            assembly: typeof(OpenIddictOptions).GetTypeInfo().Assembly,
                            baseNamespace: typeof(OpenIddictOptions).Namespace);
                    });

                // Register the sign-in manager in the isolated container.
                services.AddScoped(provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null);

                    // Resolve the sign-in manager from the parent container.
                    return container.GetRequiredService<SignInManager<TUser>>();
                });

                // Register the user manager in the isolated container.
                services.AddScoped(provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null);

                    // Resolve the user manager from the parent container.
                    return container.GetRequiredService<UserManager<TUser>>();
                });

                // Register the OpenIddict context in the isolated container.
                services.AddScoped(provider => {
                    var accessor = provider.GetRequiredService<IHttpContextAccessor>();
                    var container = (IServiceProvider) accessor.HttpContext.Items[typeof(IServiceProvider)];
                    Debug.Assert(container != null);

                    // Resolve the EntityFramework context from the parent container.
                    return container.GetRequiredService<TContext>();
                });
            });
        }
    }
}