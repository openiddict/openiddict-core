/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Routing;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.AdminApi;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Exposes extensions allowing to map the OpenIddict admin API endpoints.
/// </summary>
public static class OpenIddictServerAspNetCoreAdminApiEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the OpenIddict admin API endpoints (applications, scopes, authorizations, tokens and automatic keys)
    /// under the specified route prefix. All the endpoints require the specified authorization policy.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///   <item><description>The endpoints use the untyped managers registered by <c>services.AddOpenIddict().AddCore()</c>.</description></item>
    ///   <item><description>Requests sending a body (POST/PATCH) must use the <c>application/json</c> content type.</description></item>
    ///   <item><description>The authentication and authorization middleware must be registered.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <param name="policy">The name of the authorization policy required to access the endpoints.</param>
    /// <param name="prefix">The route prefix (by default, <see cref="OpenIddictServerAspNetCoreDefaults.AdminApiRoutePrefix"/>).</param>
    /// <returns>The <see cref="RouteGroupBuilder"/> containing the admin API endpoints.</returns>
    public static RouteGroupBuilder MapOpenIddictAdminApi(this IEndpointRouteBuilder endpoints, string policy,
        [StringSyntax("Route")] string prefix = OpenIddictServerAspNetCoreDefaults.AdminApiRoutePrefix)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrEmpty(policy);
        ArgumentNullException.ThrowIfNull(prefix);

        var group = endpoints.MapGroup(prefix);
        group.RequireAuthorization(policy);

        var applications = group.MapGroup(Paths.Applications);
        applications.MapGet(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.ListApplicationsAsync);
        applications.MapPost(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.CreateApplicationAsync);
        applications.MapGet("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.GetApplicationAsync);
        applications.MapMethods("{id}", [HttpMethods.Patch], OpenIddictServerAspNetCoreAdminApiEndpoints.UpdateApplicationAsync);
        applications.MapDelete("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.DeleteApplicationAsync);

        var scopes = group.MapGroup(Paths.Scopes);
        scopes.MapGet(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.ListScopesAsync);
        scopes.MapPost(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.CreateScopeAsync);
        scopes.MapGet("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.GetScopeAsync);
        scopes.MapMethods("{id}", [HttpMethods.Patch], OpenIddictServerAspNetCoreAdminApiEndpoints.UpdateScopeAsync);
        scopes.MapDelete("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.DeleteScopeAsync);

        var authorizations = group.MapGroup(Paths.Authorizations);
        authorizations.MapGet(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.ListAuthorizationsAsync);
        authorizations.MapPost(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.CreateAuthorizationAsync);
        authorizations.MapGet("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.GetAuthorizationAsync);
        authorizations.MapDelete("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.DeleteAuthorizationAsync);
        authorizations.MapPost("{id}/" + Paths.Revoke, OpenIddictServerAspNetCoreAdminApiEndpoints.RevokeAuthorizationAsync);

        var tokens = group.MapGroup(Paths.Tokens);
        tokens.MapGet(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.ListTokensAsync);
        tokens.MapGet("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.GetTokenAsync);
        tokens.MapDelete("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.DeleteTokenAsync);
        tokens.MapPost("{id}/" + Paths.Revoke, OpenIddictServerAspNetCoreAdminApiEndpoints.RevokeTokenAsync);

        var keys = group.MapGroup(Paths.Keys);
        keys.MapGet(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.ListKeysAsync);
        keys.MapGet("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.GetKeyAsync);
        keys.MapPost("{id}/" + Paths.Revoke, OpenIddictServerAspNetCoreAdminApiEndpoints.RevokeKeyAsync);

        var sessions = group.MapGroup(Paths.Sessions);
        sessions.MapGet(string.Empty, OpenIddictServerAspNetCoreAdminApiEndpoints.ListSessionsAsync);
        sessions.MapGet("{id}", OpenIddictServerAspNetCoreAdminApiEndpoints.GetSessionAsync);
        sessions.MapPost("{id}/" + Paths.Terminate, OpenIddictServerAspNetCoreAdminApiEndpoints.TerminateSessionAsync);

        return group;
    }
}
