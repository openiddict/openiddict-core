using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Server;
using Microsoft.AspNet.Builder.Internal;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.FileProviders;
using Microsoft.AspNet.Hosting;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.StaticFiles;
using Microsoft.Dnx.Runtime;
using Microsoft.Dnx.Runtime.Infrastructure;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Internal;
using Microsoft.Framework.Logging;
using OpenIddict;

#if DNX451
using Microsoft.Owin.Builder;
using Microsoft.Owin.BuilderProperties;
using NWebsec.Owin;
using Owin;
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
                builder.UseOwinAppBuilder(owin => {
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

        // Note: remove when https://github.com/aspnet-contrib/AspNet.Hosting.Extensions/pull/1 is merged.
        internal static IApplicationBuilder Isolate(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<IApplicationBuilder> configuration,
            [NotNull] Action<IServiceCollection> serviceConfiguration) {
            var services = new ServiceCollection();

            // Retrieve the runtime services from the host provider.
            var manifest = CallContextServiceLocator.Locator.ServiceProvider.GetService<IRuntimeServices>();
            if (manifest != null) {
                foreach (var service in manifest.Services) {
                    services.AddTransient(service, sp => CallContextServiceLocator.Locator.ServiceProvider.GetService(service));
                }
            }

            services.AddLogging();

            // Copy the services added by the hosting layer.
            services.AddInstance(app.ApplicationServices.GetRequiredService<IApplicationEnvironment>());
            services.AddInstance(app.ApplicationServices.GetRequiredService<IApplicationLifetime>());
            services.AddInstance(app.ApplicationServices.GetRequiredService<IHostingEnvironment>());
            services.AddInstance(app.ApplicationServices.GetRequiredService<ILoggerFactory>());
            services.AddInstance(app.ApplicationServices.GetRequiredService<IHttpContextAccessor>());
            services.AddInstance(app.ApplicationServices.GetRequiredService<TelemetrySource>());
            services.AddInstance(app.ApplicationServices.GetRequiredService<TelemetryListener>());

            serviceConfiguration(services);
            var provider = services.BuildServiceProvider();

            var builder = new ApplicationBuilder(null);
            builder.ApplicationServices = provider;

            builder.Use(next => async context => {
                var priorApplicationServices = context.ApplicationServices;
                var scopeFactory = provider.GetRequiredService<IServiceScopeFactory>();

                // Store the original request services in the current ASP.NET context.
                context.Items[typeof(IServiceProvider)] = context.RequestServices;

                try {
                    using (var scope = scopeFactory.CreateScope()) {
                        context.ApplicationServices = provider;
                        context.RequestServices = scope.ServiceProvider;

                        await next(context);
                    }
                }
                finally {
                    context.RequestServices = null;
                    context.ApplicationServices = priorApplicationServices;
                }
            });

            configuration(builder);

            return app.Use(next => {
                // Run the rest of the pipeline in the original context,
                // with the services defined by the parent application builder.
                builder.Run(async context => {
                    var priorApplicationServices = context.ApplicationServices;
                    var scopeFactory = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>();

                    try {
                        using (var scope = scopeFactory.CreateScope()) {
                            context.ApplicationServices = app.ApplicationServices;
                            context.RequestServices = scope.ServiceProvider;

                            await next(context);
                        }
                    }
                    finally {
                        context.RequestServices = null;
                        context.ApplicationServices = priorApplicationServices;
                    }
                });

                var branch = builder.Build();

                return context => branch(context);
            });
        }

#if DNX451
        // Note: remove when this extension is moved to https://github.com/aspnet-contrib/AspNet.Hosting.Extensions
        internal static IApplicationBuilder UseOwinAppBuilder(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<IAppBuilder> configuration) {
            return app.UseOwin(setup => setup(next => {
                var builder = new AppBuilder();
                var lifetime = app.ApplicationServices.GetService<IApplicationLifetime>();

                var properties = new AppProperties(builder.Properties);
                properties.AppName = app.ApplicationServices.GetApplicationUniqueIdentifier();
                properties.OnAppDisposing = lifetime?.ApplicationStopping ?? CancellationToken.None;
                properties.DefaultApp = next;

                configuration(builder);

                return builder.Build<Func<IDictionary<string, object>, Task>>();
            }));
        }
#endif
    }
}