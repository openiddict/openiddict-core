/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Server.AspNetCore.AdminUI.OpenIddictServerAspNetCoreAdminUIConstants;

namespace OpenIddict.Server.AspNetCore.AdminUI;

/// <summary>
/// Contains the logic used to map the admin UI forms to the OpenIddict descriptors.
/// </summary>
internal static class OpenIddictServerAspNetCoreAdminUIForms
{
    public static ImmutableArray<string> KnownApplicationTypes { get; } = [ApplicationTypes.Web, ApplicationTypes.Native];

    public static ImmutableArray<string> KnownClientTypes { get; } = [ClientTypes.Confidential, ClientTypes.Public];

    public static ImmutableArray<string> KnownConsentTypes { get; } =
    [
        ConsentTypes.Explicit, ConsentTypes.External, ConsentTypes.Implicit, ConsentTypes.Systematic
    ];

    public static ImmutableArray<string> KnownPermissions { get; } =
    [
        Permissions.Endpoints.Authorization,
        Permissions.Endpoints.BackchannelAuthentication,
        Permissions.Endpoints.DeviceAuthorization,
        Permissions.Endpoints.EndSession,
        Permissions.Endpoints.Introspection,
        Permissions.Endpoints.PushedAuthorization,
        Permissions.Endpoints.Revocation,
        Permissions.Endpoints.Token,

        Permissions.GrantTypes.AuthorizationCode,
        Permissions.GrantTypes.Ciba,
        Permissions.GrantTypes.ClientCredentials,
        Permissions.GrantTypes.DeviceCode,
        Permissions.GrantTypes.Implicit,
        Permissions.GrantTypes.Password,
        Permissions.GrantTypes.RefreshToken,
        Permissions.GrantTypes.TokenExchange,

        Permissions.ResponseTypes.Code,
        Permissions.ResponseTypes.CodeIdToken,
        Permissions.ResponseTypes.CodeIdTokenToken,
        Permissions.ResponseTypes.CodeToken,
        Permissions.ResponseTypes.IdToken,
        Permissions.ResponseTypes.IdTokenToken,
        Permissions.ResponseTypes.None,
        Permissions.ResponseTypes.Token,

        Permissions.Scopes.Address,
        Permissions.Scopes.Email,
        Permissions.Scopes.Phone,
        Permissions.Scopes.Profile,
        Permissions.Scopes.Roles
    ];

    public static ImmutableArray<string> KnownRequirements { get; } =
    [
        Requirements.Features.DPoP,
        Requirements.Features.ProofKeyForCodeExchange,
        Requirements.Features.PushedAuthorizationRequests,
        Requirements.Features.SignedRequestObjects
    ];

    public static ImmutableArray<string> KnownStatuses { get; } =
    [
        Statuses.Inactive, Statuses.Redeemed, Statuses.Rejected, Statuses.Revoked, Statuses.Valid
    ];

    /// <summary>
    /// Applies the values of the application form to the specified descriptor.
    /// </summary>
    /// <remarks>The client secret is deliberately not handled by this method.</remarks>
    /// <param name="form">The form.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <returns>The validation errors, if any.</returns>
    public static List<string> ReadApplication(IFormCollection form, OpenIddictApplicationDescriptor descriptor)
    {
        List<string> errors = [];

        descriptor.ClientId        = GetString(form, FormFields.ClientId);
        descriptor.DisplayName     = GetString(form, FormFields.DisplayName);
        descriptor.ApplicationType = GetChoice(form, FormFields.ApplicationType, KnownApplicationTypes, descriptor.ApplicationType, errors);
        descriptor.ClientType      = GetChoice(form, FormFields.ClientType, KnownClientTypes, descriptor.ClientType, errors);
        descriptor.ConsentType     = GetChoice(form, FormFields.ConsentType, KnownConsentTypes, descriptor.ConsentType, errors);

        ReadValues(form, FormFields.Permissions, FormFields.AdditionalPermissions, descriptor.Permissions);
        ReadValues(form, FormFields.Requirements, FormFields.AdditionalRequirements, descriptor.Requirements);
        ReadUris(form, FormFields.RedirectUris, descriptor.RedirectUris, errors);
        ReadUris(form, FormFields.PostLogoutRedirectUris, descriptor.PostLogoutRedirectUris, errors);
        ReadSettings(form, descriptor.Settings, errors);

        var set = GetString(form, FormFields.JsonWebKeySet);
        var remove = IsChecked(form, FormFields.RemoveJsonWebKeySet);

        if (set is not null && remove)
        {
            errors.Add(SR.FormatID2343(FormFields.JsonWebKeySet, FormFields.RemoveJsonWebKeySet));
        }

        else if (remove)
        {
            descriptor.JsonWebKeySet = null;
        }

        // Note: an empty field keeps the existing key set, as the private
        // key parameters it may contain are never sent back to the browser.
        else if (set is not null)
        {
            try
            {
                descriptor.JsonWebKeySet = JsonWebKeySet.Create(set);
            }

            catch (Exception exception) when (exception is ArgumentException or JsonException or FormatException)
            {
                errors.Add(SR.FormatID2341(FormFields.JsonWebKeySet));
            }
        }

        return errors;
    }

    /// <summary>
    /// Applies the values of the scope form to the specified descriptor.
    /// </summary>
    /// <param name="form">The form.</param>
    /// <param name="descriptor">The descriptor.</param>
    /// <returns>The validation errors, if any.</returns>
    public static List<string> ReadScope(IFormCollection form, OpenIddictScopeDescriptor descriptor)
    {
        descriptor.Name        = GetString(form, FormFields.Name);
        descriptor.DisplayName = GetString(form, FormFields.DisplayName);
        descriptor.Description = GetString(form, FormFields.Description);

        ReadValues(form, name: null, FormFields.Resources, descriptor.Resources);

        return [];
    }

    public static string? GetString(IFormCollection form, string name)
        => ((string?) form[name])?.Trim() is { Length: > 0 } value ? value : null;

    public static bool IsChecked(IFormCollection form, string name)
        => string.Equals(form[name], "true", StringComparison.OrdinalIgnoreCase);

    public static string[] SplitLines(string? value)
        => value?.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [];

    private static string? GetChoice(IFormCollection form, string name,
        ImmutableArray<string> choices, string? current, List<string> errors)
    {
        // Note: custom values (e.g application or consent types not known by the admin UI) can't be
        // selected by the user, but are rendered as an additional option when they are already stored
        // so that saving the form doesn't silently erase them: such values are always accepted as-is.
        var value = GetString(form, name);
        if (value is not null && !choices.Contains(value, StringComparer.Ordinal) &&
            !string.Equals(value, current, StringComparison.Ordinal))
        {
            errors.Add(SR.FormatID2341(name));
            return null;
        }

        return value;
    }

    private static void ReadValues(IFormCollection form, string? name, string additional, HashSet<string> values)
    {
        values.Clear();

        if (name is not null)
        {
            foreach (var value in form[name])
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    values.Add(value.Trim());
                }
            }
        }

        foreach (var value in SplitLines(form[additional]))
        {
            values.Add(value);
        }
    }

    private static void ReadUris(IFormCollection form, string name, HashSet<Uri> values, List<string> errors)
    {
        values.Clear();

        foreach (var value in SplitLines(form[name]))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
            {
                errors.Add(SR.FormatID2341(name));
                return;
            }

            values.Add(uri);
        }
    }

    private static void ReadSettings(IFormCollection form, Dictionary<string, string> values, List<string> errors)
    {
        values.Clear();

        foreach (var line in SplitLines(form[FormFields.Settings]))
        {
            var index = line.IndexOf('=');
            if (index <= 0 || string.IsNullOrWhiteSpace(line[..index]))
            {
                errors.Add(SR.FormatID2341(FormFields.Settings));
                return;
            }

            values[line[..index].Trim()] = line[(index + 1)..].Trim();
        }
    }
}
