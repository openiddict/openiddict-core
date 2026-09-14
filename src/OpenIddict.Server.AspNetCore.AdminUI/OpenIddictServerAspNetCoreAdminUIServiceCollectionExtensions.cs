/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Server.AspNetCore.AdminUI;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes extensions allowing to register the OpenIddict admin UI services.
/// </summary>
public static class OpenIddictServerAspNetCoreAdminUIServiceCollectionExtensions
{
    /// <summary>
    /// Registers the services required by the OpenIddict admin UI (Razor components rendering and antiforgery).
    /// </summary>
    /// <remarks>This extension can be safely called multiple times.</remarks>
    /// <param name="services">The services collection.</param>
    /// <param name="configuration">The delegate used to configure the admin UI options, if applicable.</param>
    /// <returns>The <see cref="IServiceCollection"/> instance.</returns>
    [RequiresUnreferencedCode("The OpenIddict admin UI uses Razor components, that are not compatible with trimming.")]
    public static IServiceCollection AddOpenIddictAdminUI(this IServiceCollection services,
        Action<OpenIddictServerAspNetCoreAdminUIOptions>? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddRazorComponents();
        services.AddAntiforgery();

        services.TryAddSingleton<OpenIddictServerAspNetCoreAdminUIMarker>();

        var builder = services.AddOptions<OpenIddictServerAspNetCoreAdminUIOptions>()
            .Validate(static options => options.PageSize is >= 1 and <= 1000, SR.GetResourceString(SR.ID0682));

        if (configuration is not null)
        {
            builder.Configure(configuration);
        }

        return services;
    }
}
