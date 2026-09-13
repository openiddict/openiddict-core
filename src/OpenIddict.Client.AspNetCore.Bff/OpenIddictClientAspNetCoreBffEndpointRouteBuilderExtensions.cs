/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Client.AspNetCore.Bff;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Exposes extensions allowing to map the OpenIddict backend-for-frontend (BFF) endpoints and middleware.
/// </summary>
public static class OpenIddictClientAspNetCoreBffEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the login, logout, user, back-channel logout and callback BFF endpoints
    /// using the paths configured in <see cref="OpenIddictClientAspNetCoreBffOptions"/>.
    /// </summary>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>A <see cref="IEndpointConventionBuilder"/> applying conventions to all the BFF endpoints.</returns>
    public static IEndpointConventionBuilder MapOpenIddictBffEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetService<IOptionsMonitor<OpenIddictClientAspNetCoreBffOptions>>()?.CurrentValue ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0561));

        return new CompositeEndpointConventionBuilder(
        [
            endpoints.MapGet(options.LoginPath, OpenIddictClientAspNetCoreBffEndpoints.LoginAsync),
            endpoints.MapMethods(options.RedirectionPath, [HttpMethods.Get, HttpMethods.Post], OpenIddictClientAspNetCoreBffEndpoints.LoginCallbackAsync),
            endpoints.MapGet(options.LogoutPath, OpenIddictClientAspNetCoreBffEndpoints.LogoutAsync),
            endpoints.MapMethods(options.PostLogoutRedirectionPath, [HttpMethods.Get, HttpMethods.Post], OpenIddictClientAspNetCoreBffEndpoints.LogoutCallbackAsync),
            endpoints.MapGet(options.UserPath, OpenIddictClientAspNetCoreBffEndpoints.UserAsync),
            endpoints.MapPost(options.BackchannelLogoutPath, OpenIddictClientAspNetCoreBffEndpoints.BackchannelLogoutAsync)
        ]);
    }

    /// <summary>
    /// Marks the endpoint as a BFF API endpoint: requests must contain the antiforgery header (unless disabled)
    /// and unauthenticated requests receive 401 responses instead of being redirected to the login page.
    /// </summary>
    /// <remarks>This requires registering the BFF middleware using <see cref="UseOpenIddictBff(IApplicationBuilder)"/>.</remarks>
    /// <typeparam name="TBuilder">The type of the endpoint convention builder.</typeparam>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <param name="disableAntiforgeryCheck">Whether the antiforgery header check should be disabled.</param>
    /// <returns>The endpoint convention builder.</returns>
    public static TBuilder AsOpenIddictBffApiEndpoint<TBuilder>(this TBuilder builder, bool disableAntiforgeryCheck = false)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        return builder.WithMetadata(new OpenIddictClientAspNetCoreBffApiEndpointMetadata
        {
            DisableAntiforgeryCheck = disableAntiforgeryCheck
        });
    }

    /// <summary>
    /// Registers the BFF middleware enforcing the antiforgery header check on BFF API endpoints and YARP routes.
    /// </summary>
    /// <remarks>This middleware must be registered after <c>UseRouting()</c> and <c>UseAuthentication()</c>.</remarks>
    /// <param name="app">The application builder.</param>
    /// <returns>The <see cref="IApplicationBuilder"/> instance.</returns>
    public static IApplicationBuilder UseOpenIddictBff(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseMiddleware<OpenIddictClientAspNetCoreBffMiddleware>();
    }

    private sealed class CompositeEndpointConventionBuilder(IEndpointConventionBuilder[] builders) : IEndpointConventionBuilder
    {
        public void Add(Action<EndpointBuilder> convention)
        {
            foreach (var builder in builders)
            {
                builder.Add(convention);
            }
        }

        public void Finally(Action<EndpointBuilder> convention)
        {
            foreach (var builder in builders)
            {
                builder.Finally(convention);
            }
        }
    }
}
