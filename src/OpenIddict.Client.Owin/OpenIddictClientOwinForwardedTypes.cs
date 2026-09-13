/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;

namespace OpenIddict.Client.Owin;

/// <summary>
/// Resolves the forwarded authentication types managed by the OpenIddict OWIN client host,
/// including the provider names of the dynamic client registrations, if applicable.
/// </summary>
internal static class OpenIddictClientOwinForwardedTypes
{
    /// <summary>
    /// Resolves the forwarded authentication type corresponding to the specified type.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <param name="options">The OWIN client options.</param>
    /// <param name="type">The authentication type.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authentication description, or <see langword="null"/> if the type is not a forwarded type.</returns>
    public static async ValueTask<AuthenticationDescription?> FindAsync(IServiceProvider provider,
        OpenIddictClientOwinOptions options, string type, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(type) ||
            string.Equals(type, OpenIddictClientOwinDefaults.AuthenticationType, StringComparison.Ordinal))
        {
            return null;
        }

        // Note: explicitly registered (or static) forwarded authentication types always take precedence.
        for (var index = 0; index < options.ForwardedAuthenticationTypes.Count; index++)
        {
            var description = options.ForwardedAuthenticationTypes[index];
            if (string.Equals(description.AuthenticationType, type, StringComparison.Ordinal))
            {
                return description;
            }
        }

        if (options.DisableAutomaticAuthenticationTypeForwarding)
        {
            return null;
        }

        // Resolve the registrations whose provider name matches the requested type: if a single
        // registration is found, consider the type as a forwarded authentication type.
        OpenIddictClientRegistration? result = null;

        foreach (var source in provider.GetServices<IOpenIddictClientRegistrationProvider>())
        {
            foreach (var registration in await source.FindByProviderNameAsync(type, cancellationToken))
            {
                if (result is not null && !ReferenceEquals(result, registration))
                {
                    return null;
                }

                result = registration;
            }
        }

        return result is not null ? CreateDescription(result) : null;
    }

    /// <summary>
    /// Lists the forwarded authentication types.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    /// <param name="options">The OWIN client options.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authentication descriptions.</returns>
    public static async ValueTask<List<AuthenticationDescription>> ListAsync(IServiceProvider provider,
        OpenIddictClientOwinOptions options, CancellationToken cancellationToken)
    {
        var descriptions = new List<AuthenticationDescription>(options.ForwardedAuthenticationTypes);

        if (options.DisableAutomaticAuthenticationTypeForwarding)
        {
            return descriptions;
        }

        var registrations = new List<OpenIddictClientRegistration>();

        foreach (var source in provider.GetServices<IOpenIddictClientRegistrationProvider>())
        {
            registrations.AddRange(await source.ListAsync(cancellationToken));
        }

        foreach (var group in registrations
            .Where(static registration => !string.IsNullOrEmpty(registration.ProviderName))
            .GroupBy(static registration => registration.ProviderName!, StringComparer.Ordinal)
            .Where(static group => group.Count() is 1))
        {
            if (!descriptions.Exists(description => string.Equals(description.AuthenticationType, group.Key, StringComparison.Ordinal)))
            {
                descriptions.Add(CreateDescription(group.First()));
            }
        }

        return descriptions;
    }

    private static AuthenticationDescription CreateDescription(OpenIddictClientRegistration registration)
    {
        var description = new AuthenticationDescription
        {
            AuthenticationType = registration.ProviderName
        };

        // Note: the AuthenticationDescription.Caption property setter doesn't no-op
        // when a null or empty display name is set. To ensure the "Caption" property
        // is not added to AuthenticationDescription.Properties when a null display
        // name is set, a null check is always performed first before assigning it.
        if (!string.IsNullOrEmpty(registration.ProviderDisplayName))
        {
            description.Caption = registration.ProviderDisplayName;
        }

        return description;
    }
}
