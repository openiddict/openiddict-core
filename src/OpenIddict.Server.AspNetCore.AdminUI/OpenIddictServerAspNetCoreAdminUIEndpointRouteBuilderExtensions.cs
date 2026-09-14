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

        group.MapGet(string.Empty, handlers.Home);
        group.MapGet(Paths.Stylesheet, OpenIddictServerAspNetCoreAdminUIEndpoints.StylesheetAsync);

        group.MapGet(Paths.Applications, handlers.ListApplicationsAsync);
        group.MapGet(Paths.Applications + "/" + Paths.New, handlers.NewApplicationAsync);
        group.MapPost(Paths.Applications + "/" + Paths.New, handlers.CreateApplicationAsync);
        group.MapGet(Paths.Applications + "/{id}", handlers.EditApplicationAsync);
        group.MapPost(Paths.Applications + "/{id}", handlers.UpdateApplicationAsync);
        group.MapPost(Paths.Applications + "/{id}/" + Paths.Secret, handlers.ChangeApplicationSecretAsync);
        group.MapPost(Paths.Applications + "/{id}/" + Paths.Delete, handlers.DeleteApplicationAsync);

        group.MapGet(Paths.Scopes, handlers.ListScopesAsync);
        group.MapGet(Paths.Scopes + "/" + Paths.New, handlers.NewScopeAsync);
        group.MapPost(Paths.Scopes + "/" + Paths.New, handlers.CreateScopeAsync);
        group.MapGet(Paths.Scopes + "/{id}", handlers.EditScopeAsync);
        group.MapPost(Paths.Scopes + "/{id}", handlers.UpdateScopeAsync);
        group.MapPost(Paths.Scopes + "/{id}/" + Paths.Delete, handlers.DeleteScopeAsync);

        group.MapGet(Paths.Authorizations, handlers.ListAuthorizationsAsync);
        group.MapGet(Paths.Authorizations + "/{id}", handlers.ShowAuthorizationAsync);
        group.MapPost(Paths.Authorizations + "/{id}/" + Paths.Revoke, handlers.RevokeAuthorizationAsync);

        group.MapGet(Paths.Tokens, handlers.ListTokensAsync);
        group.MapGet(Paths.Tokens + "/{id}", handlers.ShowTokenAsync);
        group.MapPost(Paths.Tokens + "/{id}/" + Paths.Revoke, handlers.RevokeTokenAsync);

        group.MapGet(Paths.Keys, handlers.ListKeysAsync);
        group.MapPost(Paths.Keys + "/{id}/" + Paths.Revoke, handlers.RevokeKeyAsync);

        return group;
    }
}
