/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Exposes the store operations shared by the OpenIddict administration surfaces
/// (the admin API and the admin UI), so that both apply the same rules.
/// </summary>
public static class OpenIddictServerAspNetCoreAdminOperations
{
    // Private (RSA, EC, OKP, AKP) and symmetric (oct) key parameters.
    // See https://datatracker.ietf.org/doc/html/rfc7518#section-6 for more information.
    private static readonly HashSet<string> PrivateJsonWebKeyParameters = new(StringComparer.Ordinal)
    {
        "d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi"
    };

    /// <summary>
    /// Resolves the identifier and the descriptor of the specified application.
    /// </summary>
    /// <remarks>The returned descriptor contains the stored (hashed) client secret, that must never be displayed.</remarks>
    /// <param name="manager">The application manager.</param>
    /// <param name="application">The application.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The identifier and the descriptor of the application.</returns>
    public static async ValueTask<(string? Identifier, OpenIddictApplicationDescriptor Descriptor)> DescribeApplicationAsync(
        IOpenIddictApplicationManager manager, object application, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(application);

        var descriptor = new OpenIddictApplicationDescriptor();
        await manager.PopulateAsync(descriptor, application, cancellationToken);

        return (await manager.GetIdAsync(application, cancellationToken), descriptor);
    }

    /// <summary>
    /// Resolves the identifier and the descriptor of the specified scope.
    /// </summary>
    /// <param name="manager">The scope manager.</param>
    /// <param name="scope">The scope.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The identifier and the descriptor of the scope.</returns>
    public static async ValueTask<(string? Identifier, OpenIddictScopeDescriptor Descriptor)> DescribeScopeAsync(
        IOpenIddictScopeManager manager, object scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(scope);

        var descriptor = new OpenIddictScopeDescriptor();
        await manager.PopulateAsync(descriptor, scope, cancellationToken);

        return (await manager.GetIdAsync(scope, cancellationToken), descriptor);
    }

    /// <summary>
    /// Resolves the identifier and the descriptor of the specified authorization.
    /// </summary>
    /// <param name="manager">The authorization manager.</param>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The identifier and the descriptor of the authorization.</returns>
    public static async ValueTask<(string? Identifier, OpenIddictAuthorizationDescriptor Descriptor)> DescribeAuthorizationAsync(
        IOpenIddictAuthorizationManager manager, object authorization, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(authorization);

        var descriptor = new OpenIddictAuthorizationDescriptor();
        await manager.PopulateAsync(descriptor, authorization, cancellationToken);

        return (await manager.GetIdAsync(authorization, cancellationToken), descriptor);
    }

    /// <summary>
    /// Resolves the identifier and the descriptor of the specified token.
    /// </summary>
    /// <remarks>The returned descriptor contains the token payload, that must never be displayed.</remarks>
    /// <param name="manager">The token manager.</param>
    /// <param name="token">The token.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The identifier and the descriptor of the token.</returns>
    public static async ValueTask<(string? Identifier, OpenIddictTokenDescriptor Descriptor)> DescribeTokenAsync(
        IOpenIddictTokenManager manager, object token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(token);

        var descriptor = new OpenIddictTokenDescriptor();
        await manager.PopulateAsync(descriptor, token, cancellationToken);

        return (await manager.GetIdAsync(token, cancellationToken), descriptor);
    }

    /// <summary>
    /// Resolves the identifier and the descriptor of the specified key.
    /// </summary>
    /// <remarks>The returned descriptor contains the protected key material, that must never be displayed.</remarks>
    /// <param name="manager">The key manager.</param>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The identifier and the descriptor of the key.</returns>
    public static async ValueTask<(string? Identifier, OpenIddictKeyDescriptor Descriptor)> DescribeKeyAsync(
        IOpenIddictKeyManager manager, object key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(key);

        var descriptor = new OpenIddictKeyDescriptor();
        await manager.PopulateAsync(descriptor, key, cancellationToken);

        return (await manager.GetIdAsync(key, cancellationToken), descriptor);
    }

    /// <summary>
    /// Resolves the identifier and the descriptor of the specified session.
    /// </summary>
    /// <remarks>The returned descriptor contains the principal attached to the session, that must never be displayed.</remarks>
    /// <param name="manager">The session manager.</param>
    /// <param name="session">The session.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The identifier and the descriptor of the session.</returns>
    public static async ValueTask<(string? Identifier, OpenIddictSessionDescriptor Descriptor)> DescribeSessionAsync(
        IOpenIddictSessionManager manager, object session, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(session);

        var descriptor = new OpenIddictSessionDescriptor();
        await manager.PopulateAsync(descriptor, session, cancellationToken);

        return (await manager.GetIdAsync(session, cancellationToken), descriptor);
    }

    /// <summary>
    /// Lists the authorizations matching the specified filters (a <see langword="null"/> filter is ignored).
    /// </summary>
    /// <param name="manager">The authorization manager.</param>
    /// <param name="subject">The subject, if applicable.</param>
    /// <param name="applicationId">The application identifier, if applicable.</param>
    /// <param name="status">The status, if applicable.</param>
    /// <param name="type">The type, if applicable.</param>
    /// <param name="count">The maximum number of entries to return.</param>
    /// <param name="offset">The number of entries to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The authorizations.</returns>
    public static IAsyncEnumerable<object> ListAuthorizationsAsync(IOpenIddictAuthorizationManager manager,
        string? subject, string? applicationId, string? status, string? type,
        int count, int offset, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);

        return subject is null && applicationId is null && status is null && type is null ?
            manager.ListAsync(count, offset, cancellationToken) :
            PaginateAsync(manager.FindAsync((subject, applicationId, status, type, null), cancellationToken),
                count, offset, cancellationToken);
    }

    /// <summary>
    /// Lists the tokens matching the specified filters (a <see langword="null"/> filter is ignored).
    /// </summary>
    /// <param name="manager">The token manager.</param>
    /// <param name="subject">The subject, if applicable.</param>
    /// <param name="applicationId">The application identifier, if applicable.</param>
    /// <param name="status">The status, if applicable.</param>
    /// <param name="type">The type, if applicable.</param>
    /// <param name="count">The maximum number of entries to return.</param>
    /// <param name="offset">The number of entries to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The tokens.</returns>
    public static IAsyncEnumerable<object> ListTokensAsync(IOpenIddictTokenManager manager,
        string? subject, string? applicationId, string? status, string? type,
        int count, int offset, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);

        return subject is null && applicationId is null && status is null && type is null ?
            manager.ListAsync(count, offset, cancellationToken) :
            PaginateAsync(manager.FindAsync((subject, applicationId, status, type), cancellationToken),
                count, offset, cancellationToken);
    }

    /// <summary>
    /// Lists the sessions matching the specified filters (a <see langword="null"/> filter is ignored).
    /// </summary>
    /// <param name="manager">The session manager.</param>
    /// <param name="subject">The subject, if applicable.</param>
    /// <param name="loginId">The login identifier, if applicable.</param>
    /// <param name="applicationId">The application identifier, if applicable.</param>
    /// <param name="status">The status, if applicable.</param>
    /// <param name="count">The maximum number of entries to return.</param>
    /// <param name="offset">The number of entries to skip.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The sessions.</returns>
    public static IAsyncEnumerable<object> ListSessionsAsync(IOpenIddictSessionManager manager,
        string? subject, string? loginId, string? applicationId, string? status,
        int count, int offset, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(count);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);

        return subject is null && loginId is null && applicationId is null && status is null ?
            manager.ListAsync(count, offset, cancellationToken) :
            PaginateAsync(manager.FindAsync((subject, loginId, applicationId, null, status), cancellationToken),
                count, offset, cancellationToken);
    }

    /// <summary>
    /// Revokes the specified authorization and, if a token manager is specified,
    /// the tokens attached to it so that they are no longer considered valid
    /// (independently of whether token validation checks the status of the authorization entry).
    /// </summary>
    /// <param name="manager">The authorization manager.</param>
    /// <param name="tokens">The token manager, if available.</param>
    /// <param name="authorization">The authorization.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the authorization was revoked, <see langword="false"/> otherwise.</returns>
    public static async ValueTask<bool> TryRevokeAuthorizationAsync(IOpenIddictAuthorizationManager manager,
        IOpenIddictTokenManager? tokens, object authorization, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(authorization);

        if (!await manager.TryRevokeAsync(authorization, cancellationToken))
        {
            return false;
        }

        if (tokens is not null && await manager.GetIdAsync(authorization, cancellationToken) is { Length: > 0 } identifier)
        {
            await tokens.RevokeByAuthorizationIdAsync(identifier, cancellationToken);
        }

        return true;
    }

    /// <summary>
    /// Revokes the specified key and, if a key ring is specified, discards the
    /// credentials cached by the key ring so that the revoked key is no longer used.
    /// </summary>
    /// <param name="manager">The key manager.</param>
    /// <param name="ring">The key ring, if available.</param>
    /// <param name="key">The key.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns><see langword="true"/> if the key was revoked, <see langword="false"/> otherwise.</returns>
    public static async ValueTask<bool> TryRevokeKeyAsync(IOpenIddictKeyManager manager,
        OpenIddictServerKeyRing? ring, object key, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(key);

        if (!await manager.TryRevokeAsync(key, cancellationToken))
        {
            return false;
        }

        ring?.Invalidate();

        return true;
    }

    /// <summary>
    /// Writes the specified JSON Web Key Set without the private and symmetric key parameters (that may have
    /// been attached to a client JSON Web Key Set, even if only public keys are expected).
    /// </summary>
    /// <param name="writer">The JSON writer.</param>
    /// <param name="set">The JSON Web Key Set.</param>
    public static void WritePublicJsonWebKeySet(Utf8JsonWriter writer, JsonWebKeySet set)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(set);

        using var document = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(
            set, OpenIddictSerializer.Default.JsonWebKeySet));

        writer.WriteStartObject();

        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (!property.NameEquals(JsonWebKeySetParameterNames.Keys) || property.Value.ValueKind is not JsonValueKind.Array)
            {
                property.WriteTo(writer);
                continue;
            }

            writer.WriteStartArray(property.Name);

            foreach (var key in property.Value.EnumerateArray())
            {
                if (key.ValueKind is not JsonValueKind.Object)
                {
                    continue;
                }

                writer.WriteStartObject();

                foreach (var parameter in key.EnumerateObject())
                {
                    if (!PrivateJsonWebKeyParameters.Contains(parameter.Name))
                    {
                        parameter.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        writer.WriteEndObject();
    }

    internal static async IAsyncEnumerable<object> PaginateAsync(IAsyncEnumerable<object> source,
        int count, int offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var index = 0;

        await foreach (var item in source.WithCancellation(cancellationToken))
        {
            if (index++ < offset)
            {
                continue;
            }

            yield return item;

            if (index - offset >= count)
            {
                yield break;
            }
        }
    }
}
