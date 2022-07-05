using System.Security.Claims;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Extensions;

/// <summary>
/// Exposes common helpers used by the OpenIddict assemblies.
/// </summary>
internal static class OpenIddictHelpers
{
    /// <summary>
    /// Finds the first base type that matches the specified generic type definition.
    /// </summary>
    /// <param name="type">The type to introspect.</param>
    /// <param name="definition">The generic type definition.</param>
    /// <returns>A <see cref="Type"/> instance if the base type was found, <see langword="null"/> otherwise.</returns>
    public static Type? FindGenericBaseType(Type type, Type definition)
        => FindGenericBaseTypes(type, definition).FirstOrDefault();

    /// <summary>
    /// Finds all the base types that matches the specified generic type definition.
    /// </summary>
    /// <param name="type">The type to introspect.</param>
    /// <param name="definition">The generic type definition.</param>
    /// <returns>A <see cref="Type"/> instance if the base type was found, <see langword="null"/> otherwise.</returns>
    public static IEnumerable<Type> FindGenericBaseTypes(Type type, Type definition)
    {
        if (type is null)
        {
            throw new ArgumentNullException(nameof(type));
        }

        if (definition is null)
        {
            throw new ArgumentNullException(nameof(definition));
        }

        if (!definition.IsGenericTypeDefinition)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0263), nameof(definition));
        }

        if (definition.IsInterface)
        {
            foreach (var contract in type.GetInterfaces())
            {
                if (!contract.IsGenericType && !contract.IsConstructedGenericType)
                {
                    continue;
                }

                if (contract.GetGenericTypeDefinition() == definition)
                {
                    yield return contract;
                }
            }
        }

        else
        {
            for (var candidate = type; candidate is not null; candidate = candidate.BaseType)
            {
                if (!candidate.IsGenericType && !candidate.IsConstructedGenericType)
                {
                    continue;
                }

                if (candidate.GetGenericTypeDefinition() == definition)
                {
                    yield return candidate;
                }
            }
        }
    }

    /// <summary>
    /// Extracts the parameters from the specified query string.
    /// </summary>
    /// <param name="query">The query string, which may start with a '?'.</param>
    /// <returns>The parameters extracted from the specified query string.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="query"/> is <see langword="null"/>.</exception>
    public static IReadOnlyDictionary<string, StringValues> ParseQuery(string query)
    {
        if (query is null)
        {
            throw new ArgumentNullException(nameof(query));
        }

        return query.TrimStart(Separators.QuestionMark[0])
            .Split(new[] { Separators.Ampersand[0], Separators.Semicolon[0] }, StringSplitOptions.RemoveEmptyEntries)
            .Select(parameter => parameter.Split(Separators.EqualsSign, StringSplitOptions.RemoveEmptyEntries))
            .Select(parts => (
                Key: parts[0] is string key ? Uri.UnescapeDataString(key) : null,
                Value: parts.Length > 1 && parts[1] is string value ? Uri.UnescapeDataString(value) : null))
            // Note: ignore empty values to match the logic used by OWIN for IOwinRequest.Query.
            .Where(pair => !string.IsNullOrEmpty(pair.Key) && !string.IsNullOrEmpty(pair.Value))
            .GroupBy(pair => pair.Key)
            .ToDictionary(pair => pair.Key!, pair => new StringValues(pair.Select(parts => parts.Value).ToArray()));
    }

    /// <summary>
    /// Creates a merged principal based on the specified principals.
    /// </summary>
    /// <param name="principals">The collection of principals to merge.</param>
    /// <returns>The merged principal.</returns>
    public static ClaimsPrincipal CreateMergedPrincipal(params ClaimsPrincipal?[] principals)
    {
        // Note: components like the client handler can be used as a pure OAuth 2.0 stack for
        // delegation scenarios where the identity of the user is not needed. In this case,
        // since no principal can be resolved from a token or a userinfo response to construct
        // a user identity, a fake one containing an "unauthenticated" identity (i.e with its
        // AuthenticationType property deliberately left to null) is used to allow the host
        // to return a "successful" authentication result for these delegation-only scenarios.
        if (!principals.Any(principal => principal?.Identity is ClaimsIdentity { IsAuthenticated: true }))
        {
            return new ClaimsPrincipal(new ClaimsIdentity());
        }

        // Create a new composite identity containing the claims of all the principals.
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

        foreach (var principal in principals)
        {
            // Note: the principal may be null if no value was extracted from the corresponding token.
            if (principal is null)
            {
                continue;
            }

            foreach (var claim in principal.Claims)
            {
                // If a claim with the same type and the same value already exist, skip it.
                if (identity.HasClaim(claim.Type, claim.Value))
                {
                    continue;
                }

                identity.AddClaim(claim);
            }
        }

        return new ClaimsPrincipal(identity);
    }
}
