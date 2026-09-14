/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server.AspNetCore.AdminUI;
using static OpenIddict.Server.AspNetCore.AdminUI.OpenIddictServerAspNetCoreAdminUIConstants;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Exposes extensions allowing to map the OpenIddict admin UI endpoints.
/// </summary>
public static class OpenIddictServerAspNetCoreAdminUIEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the OpenIddict admin UI pages (applications, scopes, authorizations, tokens and automatic keys)
    /// under the specified route prefix. All the pages require the specified authorization policy.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///   <item><description>The pages are rendered using static server-side rendering and don't require JavaScript.</description></item>
    ///   <item><description>The pages use the untyped managers registered by <c>services.AddOpenIddict().AddCore()</c>.</description></item>
    ///   <item><description>All the form posts require a valid antiforgery token.</description></item>
    ///   <item><description>The authentication and authorization middleware must be registered.</description></item>
    ///   <item><description>
    ///     The admin UI and the admin API (<c>MapOpenIddictAdminApi()</c>) use the same default prefix and
    ///     the same relative paths: when both are mapped, a different prefix must be used for one of them.
    ///     Endpoints mapped on the same route builder that would make the admin UI routes ambiguous are
    ///     detected when the endpoints are built and cause an <see cref="InvalidOperationException"/>.
    ///   </description></item>
    /// </list>
    /// </remarks>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="policy">The name of the authorization policy required to access the pages.</param>
    /// <param name="prefix">The route prefix (by default, <see cref="DefaultRoutePrefix"/>).</param>
    /// <returns>The <see cref="RouteGroupBuilder"/> containing the admin UI endpoints.</returns>
    public static RouteGroupBuilder MapOpenIddictAdminUI(this IEndpointRouteBuilder endpoints, string policy,
        [StringSyntax("Route")] string prefix = DefaultRoutePrefix)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(policy);
        ArgumentNullException.ThrowIfNull(prefix);

        if (endpoints.ServiceProvider.GetService<OpenIddictServerAspNetCoreAdminUIMarker>() is null)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0681));
        }

        var handlers = new OpenIddictServerAspNetCoreAdminUIEndpoints(prefix);

        var group = endpoints.MapGroup(prefix);
        group.RequireAuthorization(policy);

        // Note: MapGroup() adds a single data source to the parent route builder, that is
        // excluded from the conflict detection as it contains the admin UI endpoints.
        var detector = new OpenIddictServerAspNetCoreAdminUIConflictDetector(endpoints, endpoints.DataSources.Last(), prefix);
        ((IEndpointConventionBuilder) group).Finally(_ => detector.EnsureNoConflict());

        Map(HttpMethods.Get, string.Empty, handlers.Home);
        Map(HttpMethods.Get, Paths.Stylesheet, OpenIddictServerAspNetCoreAdminUIEndpoints.StylesheetAsync);

        Map(HttpMethods.Get, Paths.Applications, handlers.ListApplicationsAsync);
        Map(HttpMethods.Get, Paths.Applications + "/" + Paths.New, handlers.NewApplicationAsync);
        Map(HttpMethods.Post, Paths.Applications + "/" + Paths.New, handlers.CreateApplicationAsync);
        Map(HttpMethods.Get, Paths.Applications + "/{id}", handlers.EditApplicationAsync);
        Map(HttpMethods.Post, Paths.Applications + "/{id}", handlers.UpdateApplicationAsync);
        Map(HttpMethods.Post, Paths.Applications + "/{id}/" + Paths.Secret, handlers.ChangeApplicationSecretAsync);
        Map(HttpMethods.Post, Paths.Applications + "/{id}/" + Paths.Delete, handlers.DeleteApplicationAsync);

        Map(HttpMethods.Get, Paths.Scopes, handlers.ListScopesAsync);
        Map(HttpMethods.Get, Paths.Scopes + "/" + Paths.New, handlers.NewScopeAsync);
        Map(HttpMethods.Post, Paths.Scopes + "/" + Paths.New, handlers.CreateScopeAsync);
        Map(HttpMethods.Get, Paths.Scopes + "/{id}", handlers.EditScopeAsync);
        Map(HttpMethods.Post, Paths.Scopes + "/{id}", handlers.UpdateScopeAsync);
        Map(HttpMethods.Post, Paths.Scopes + "/{id}/" + Paths.Delete, handlers.DeleteScopeAsync);

        Map(HttpMethods.Get, Paths.Authorizations, handlers.ListAuthorizationsAsync);
        Map(HttpMethods.Get, Paths.Authorizations + "/{id}", handlers.ShowAuthorizationAsync);
        Map(HttpMethods.Post, Paths.Authorizations + "/{id}/" + Paths.Revoke, handlers.RevokeAuthorizationAsync);

        Map(HttpMethods.Get, Paths.Tokens, handlers.ListTokensAsync);
        Map(HttpMethods.Get, Paths.Tokens + "/{id}", handlers.ShowTokenAsync);
        Map(HttpMethods.Post, Paths.Tokens + "/{id}/" + Paths.Revoke, handlers.RevokeTokenAsync);

        Map(HttpMethods.Get, Paths.Keys, handlers.ListKeysAsync);
        Map(HttpMethods.Post, Paths.Keys + "/{id}/" + Paths.Revoke, handlers.RevokeKeyAsync);

        return group;

        void Map(string method, string path, RequestDelegate handler)
        {
            group.MapMethods(path, [method], handler);
            detector.Add(method, path);
        }
    }
}
