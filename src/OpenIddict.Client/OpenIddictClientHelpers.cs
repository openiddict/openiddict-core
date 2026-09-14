/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net.Http.Headers;
using System.Text.Json;
using static OpenIddict.Client.OpenIddictClientModels;

namespace OpenIddict.Client;

/// <summary>
/// Exposes extensions simplifying the integration with the OpenIddict client services.
/// </summary>
public static class OpenIddictClientHelpers
{
    /// <summary>
    /// Creates a <see cref="BackchannelNotification"/> from the raw HTTP request received by the client notification
    /// endpoint (CIBA ping and push modes): the bearer token is extracted from the "Authorization" header and the
    /// payload from the JSON body. This method is typically used by the ASP.NET Core and OWIN host integrations.
    /// </summary>
    /// <param name="authorization">The value of the "Authorization" header, if available.</param>
    /// <param name="type">The value of the "Content-Type" header, if available.</param>
    /// <param name="body">The request body.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>
    /// The notification or <see langword="null"/> if the request is not a valid JSON notification.
    /// </returns>
    /// <remarks>
    /// See https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.10.2.
    /// </remarks>
    public static async ValueTask<BackchannelNotification?> CreateBackchannelNotificationAsync(
        string? authorization, string? type, Stream body, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(body);

        if (string.IsNullOrEmpty(type) || !MediaTypeHeaderValue.TryParse(type, out MediaTypeHeaderValue? value) ||
            !string.Equals(value.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        JsonDocument document;

        try
        {
            document = await JsonDocument.ParseAsync(body, cancellationToken: cancellationToken);
        }

        catch (JsonException)
        {
            return null;
        }

        using (document)
        {
            if (document.RootElement.ValueKind is not JsonValueKind.Object)
            {
                return null;
            }

            return new BackchannelNotification
            {
                // Note: the authentication scheme is case-insensitive (RFC 9110, section 11.1).
                ClientNotificationToken = !string.IsNullOrEmpty(authorization) &&
                    AuthenticationHeaderValue.TryParse(authorization, out AuthenticationHeaderValue? header) &&
                    string.Equals(header.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase) ? header.Parameter : null,
                Payload = new OpenIddictResponse(document.RootElement.Clone())
            };
        }
    }

    /// <summary>
    /// Retrieves a property value from the client transaction using the specified name.
    /// </summary>
    /// <typeparam name="TProperty">The type of the property.</typeparam>
    /// <param name="transaction">The client transaction.</param>
    /// <param name="name">The property name.</param>
    /// <returns>The property value or <see langword="null"/> if it couldn't be found.</returns>
    public static TProperty? GetProperty<TProperty>(
        this OpenIddictClientTransaction transaction, string name) where TProperty : class
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (transaction.Properties.TryGetValue(name, out var property) && property is TProperty result)
        {
            return result;
        }

        return null;
    }

    /// <summary>
    /// Sets a property in the client transaction using the specified name and value.
    /// </summary>
    /// <typeparam name="TProperty">The type of the property.</typeparam>
    /// <param name="transaction">The client transaction.</param>
    /// <param name="name">The property name.</param>
    /// <param name="value">The property value.</param>
    /// <returns>The client transaction, so that calls can be easily chained.</returns>
    public static OpenIddictClientTransaction SetProperty<TProperty>(
        this OpenIddictClientTransaction transaction,
        string name, TProperty? value) where TProperty : class
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentException.ThrowIfNullOrEmpty(name);

        if (value is null)
        {
            transaction.Properties.Remove(name);
        }

        else
        {
            transaction.Properties[name] = value;
        }

        return transaction;
    }
}
