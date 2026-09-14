/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;

namespace OpenIddict.Server.AspNetCore.AdminUI;

/// <summary>
/// Contains the formatting helpers used by the admin UI pages.
/// </summary>
internal static class OpenIddictServerAspNetCoreAdminUIFormatting
{
    public const string Empty = "—";

    public static string FormatDate(DateTimeOffset? date)
        => date?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture) ?? Empty;

    public static string FormatClient(IReadOnlyDictionary<string, string> clients, string? identifier)
        => string.IsNullOrEmpty(identifier) ? Empty : clients.TryGetValue(identifier, out var client) ? client : identifier;

    public static string FormatValue(string? value) => string.IsNullOrEmpty(value) ? Empty : value;
}
