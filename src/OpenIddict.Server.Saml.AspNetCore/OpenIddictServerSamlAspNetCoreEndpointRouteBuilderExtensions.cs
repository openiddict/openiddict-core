/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server.Saml.AspNetCore;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Exposes extensions allowing to map the OpenIddict SAML 2.0 identity provider endpoints.
/// </summary>
public static class OpenIddictServerSamlAspNetCoreEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the SAML metadata, single sign-on and artifact resolution endpoints using the paths
    /// configured in <see cref="OpenIddictServerSamlAspNetCoreOptions"/>. Note: the artifact
    /// resolution endpoint returns a 404 response unless the HTTP-Artifact binding is enabled.
    /// </summary>
    /// <remarks>The endpoints must be mapped after <c>UseAuthentication()</c> is called.</remarks>
    /// <param name="endpoints">The endpoint route builder.</param>
    /// <returns>A <see cref="IEndpointConventionBuilder"/> applying conventions to all the SAML endpoints.</returns>
    public static IEndpointConventionBuilder MapOpenIddictSamlEndpoints(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetService<IOptionsMonitor<OpenIddictServerSamlAspNetCoreOptions>>()?.CurrentValue ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0571));

        return new CompositeEndpointConventionBuilder(
        [
            endpoints.MapGet(options.MetadataPath.Value!, OpenIddictServerSamlAspNetCoreEndpoints.MetadataAsync),
            endpoints.MapMethods(options.SingleSignOnPath.Value!, [HttpMethods.Get, HttpMethods.Post], OpenIddictServerSamlAspNetCoreEndpoints.SingleSignOnAsync),
            endpoints.MapPost(options.ArtifactResolutionPath.Value!, OpenIddictServerSamlAspNetCoreEndpoints.ArtifactResolutionAsync)
        ]);
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
