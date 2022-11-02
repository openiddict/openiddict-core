using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
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
    /// Adds a query string parameter to the specified <see cref="Uri"/>.
    /// </summary>
    /// <param name="address">The address, to which the query string parameter will be appended.</param>
    /// <param name="name">The name of the query string parameter to append.</param>
    /// <param name="value">The value of the query string parameter to append.</param>
    /// <returns>The final <see cref="Uri"/> instance, with the specified parameter appended.</returns>
    public static Uri AddQueryStringParameter(Uri address, string name, string? value)
    {
        if (address is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        var builder = new StringBuilder(address.Query);
        if (builder.Length > 0)
        {
            builder.Append('&');
        }

        builder.Append(Uri.EscapeDataString(name));

        if (!string.IsNullOrEmpty(value))
        {
            builder.Append('=');
            builder.Append(Uri.EscapeDataString(value));
        }

        return new UriBuilder(address) { Query = builder.ToString() }.Uri;
    }

    /// <summary>
    /// Adds query string parameters to the specified <see cref="Uri"/>.
    /// </summary>
    /// <param name="address">The address, to which the query string parameters will be appended.</param>
    /// <param name="parameters">The query string parameters to append.</param>
    /// <returns>The final <see cref="Uri"/> instance, with the specified parameters appended.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="address"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> is <see langword="null"/>.</exception>
    public static Uri AddQueryStringParameters(Uri address, IReadOnlyDictionary<string, StringValues> parameters)
    {
        if (address is null)
        {
            throw new ArgumentNullException(nameof(address));
        }

        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        if (parameters.Count is 0)
        {
            return address;
        }

        var builder = new StringBuilder(address.Query);

        foreach (var parameter in parameters)
        {
            // If the parameter doesn't include any string value,
            // only append the parameter key to the query string.
            if (parameter.Value.Count is 0)
            {
                if (builder.Length > 0)
                {
                    builder.Append('&');
                }

                builder.Append(Uri.EscapeDataString(parameter.Key));
            }

            // Otherwise, iterate the string values and create
            // a new "name=value" pair for each iterated value.
            else
            {
                foreach (var value in parameter.Value)
                {
                    if (builder.Length > 0)
                    {
                        builder.Append('&');
                    }

                    builder.Append(Uri.EscapeDataString(parameter.Key));

                    if (!string.IsNullOrEmpty(value))
                    {
                        builder.Append('=');
                        builder.Append(Uri.EscapeDataString(value));
                    }
                }
            }
        }

        return new UriBuilder(address) { Query = builder.ToString() }.Uri;
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
            .Where(pair => !string.IsNullOrEmpty(pair.Key))
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

#if SUPPORTS_ECDSA
    /// <summary>
    /// Creates a new <see cref="ECDsa"/> key.
    /// </summary>
    /// <returns>A new <see cref="ECDsa"/> key.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static ECDsa CreateEcdsaKey()
        => CryptoConfig.CreateFromName("OpenIddict ECDSA Cryptographic Provider") switch
        {
            ECDsa result => result,
            null => ECDsa.Create(),
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

    /// <summary>
    /// Creates a new <see cref="ECDsa"/> key.
    /// </summary>
    /// <param name="curve">The EC curve to use to create the key.</param>
    /// <returns>A new <see cref="ECDsa"/> key.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static ECDsa CreateEcdsaKey(ECCurve curve)
    {
        var algorithm = CryptoConfig.CreateFromName("OpenIddict ECDSA Cryptographic Provider") switch
        {
            ECDsa result => result,
            null => null,
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        // If no custom algorithm was registered, use either the static Create() API
        // on platforms that support it or create a default instance provided by the BCL.
        if (algorithm is null)
        {
            return ECDsa.Create(curve);
        }

        try
        {
            algorithm.GenerateKey(curve);
        }

        catch
        {
            algorithm.Dispose();

            throw;
        }

        return algorithm;
    }
#endif

    /// <summary>
    /// Creates a new <see cref="RSA"/> key.
    /// </summary>
    /// <param name="size">The key size to use to create the key.</param>
    /// <returns>A new <see cref="RSA"/> key.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static RSA CreateRsaKey(int size)
    {
        var algorithm = CryptoConfig.CreateFromName("OpenIddict RSA Cryptographic Provider") switch
        {
            RSA result => result,

#if SUPPORTS_RSA_KEY_CREATION_WITH_SPECIFIED_SIZE
            // Note: on .NET Framework >= 4.7.2, the new RSA.Create(int keySizeInBits) uses
            // CryptoConfig.CreateFromName("RSAPSS") internally, which returns by default
            // a RSACng instance instead of a RSACryptoServiceProvider based on CryptoAPI.
            null => RSA.Create(size),
#else
            // Note: while a RSACng object could be manually instantiated and returned on
            // .NET Framework < 4.7.2, the static RSA.Create() factory (which returns a
            // RSACryptoServiceProvider instance by default) is always preferred to RSACng
            // as this type is known to have compatibility issues on .NET Framework < 4.6.2.
            //
            // Developers who prefer using a CNG-based implementation on .NET Framework 4.6.1
            // can do so by tweaking machine.config or by using CryptoConfig.AddAlgorithm().
            null => RSA.Create(),
#endif
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        // Note: on .NET Framework, the RSA.Create() overload uses CryptoConfig.CreateFromName()
        // and always returns a RSACryptoServiceProvider instance unless the default name mapping was
        // explicitly overriden in machine.config or via CryptoConfig.AddAlgorithm(). Unfortunately,
        // RSACryptoServiceProvider still uses 1024-bit keys by default and doesn't support changing
        // the key size via RSACryptoServiceProvider.KeySize (setting it has no effect on the object).
        //
        // To ensure the key size matches the requested size, this method replaces the instance by a
        // new RSACryptoServiceProvider using the constructor allowing to override the default key size.
        try
        {
            if (algorithm.KeySize != size)
            {
                if (algorithm is RSACryptoServiceProvider)
                {
                    algorithm.Dispose();
                    algorithm = new RSACryptoServiceProvider(size);
                }

                else
                {
                    algorithm.KeySize = size;
                }

                if (algorithm.KeySize != size)
                {
                    throw new CryptographicException(SR.FormatID0059(algorithm.GetType().FullName));
                }
            }
        }

        catch
        {
            algorithm.Dispose();

            throw;
        }

        return algorithm;
    }

    /// <summary>
    /// Computes the SHA-256 hash of the specified <paramref name="data"/> array.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The SHA-256 hash of the specified <paramref name="data"/> array.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static byte[] ComputeSha256Hash(byte[] data)
    {
        var algorithm = CryptoConfig.CreateFromName("OpenIddict SHA-256 Cryptographic Provider") switch
        {
            SHA256 result => result,
            null => null,
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        // If no custom algorithm was registered, use either the static/one-shot HashData() API
        // on platforms that support it or create a default instance provided by the BCL.
        if (algorithm is null)
        {
#if SUPPORTS_ONE_SHOT_HASHING_METHODS
            return SHA256.HashData(data);
#else
            algorithm = SHA256.Create();
#endif
        }

        try
        {
            return algorithm.ComputeHash(data);
        }

        finally
        {
            algorithm.Dispose();
        }
    }

    /// <summary>
    /// Computes the SHA-384 hash of the specified <paramref name="data"/> array.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The SHA-384 hash of the specified <paramref name="data"/> array.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static byte[] ComputeSha384Hash(byte[] data)
    {
        var algorithm = CryptoConfig.CreateFromName("OpenIddict SHA-384 Cryptographic Provider") switch
        {
            SHA384 result => result,
            null => null,
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        // If no custom algorithm was registered, use either the static/one-shot HashData() API
        // on platforms that support it or create a default instance provided by the BCL.
        if (algorithm is null)
        {
#if SUPPORTS_ONE_SHOT_HASHING_METHODS
            return SHA384.HashData(data);
#else
            algorithm = SHA384.Create();
#endif
        }

        try
        {
            return algorithm.ComputeHash(data);
        }

        finally
        {
            algorithm.Dispose();
        }
    }

    /// <summary>
    /// Computes the SHA-512 hash of the specified <paramref name="data"/> array.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <returns>The SHA-512 hash of the specified <paramref name="data"/> array.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static byte[] ComputeSha512Hash(byte[] data)
    {
        var algorithm = CryptoConfig.CreateFromName("OpenIddict SHA-512 Cryptographic Provider") switch
        {
            SHA512 result => result,
            null => null,
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        // If no custom algorithm was registered, use either the static/one-shot HashData() API
        // on platforms that support it or create a default instance provided by the BCL.
        if (algorithm is null)
        {
#if SUPPORTS_ONE_SHOT_HASHING_METHODS
            return SHA512.HashData(data);
#else
            algorithm = SHA512.Create();
#endif
        }

        try
        {
            return algorithm.ComputeHash(data);
        }

        finally
        {
            algorithm.Dispose();
        }
    }

    /// <summary>
    /// Creates a new array of <see cref="byte"/> containing random data.
    /// </summary>
    /// <param name="size">The desired entropy, in bits.</param>
    /// <returns>A new array of <see cref="byte"/> containing random data.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static byte[] CreateRandomArray(int size)
    {
        var algorithm = CryptoConfig.CreateFromName("OpenIddict RNG Cryptographic Provider") switch
        {
            RandomNumberGenerator result => result,
            null => null,
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        // If no custom random number generator was registered, use either the static GetBytes() or
        // Fill() APIs on platforms that support them or create a default instance provided by the BCL.
#if SUPPORTS_ONE_SHOT_RANDOM_NUMBER_GENERATOR_METHODS
        if (algorithm is null)
        {
            return RandomNumberGenerator.GetBytes(size / 8);
        }
#endif
        var array = new byte[size / 8];

#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
        if (algorithm is null)
        {
            RandomNumberGenerator.Fill(array);
            return array;
        }
#else
        algorithm ??= RandomNumberGenerator.Create();
#endif
        try
        {
            algorithm.GetBytes(array);
        }

        finally
        {
            algorithm.Dispose();
        }

        return array;
    }

#if SUPPORTS_KEY_DERIVATION_WITH_SPECIFIED_HASH_ALGORITHM
    /// <summary>
    /// Creates a derived key based on the specified <paramref name="secret"/> using PBKDF2.
    /// </summary>
    /// <param name="secret">The secret from which the derived key is created.</param>
    /// <param name="salt">The salt.</param>
    /// <param name="algorithm">The hash algorithm to use.</param>
    /// <param name="iterations">The number of iterations to use.</param>
    /// <param name="length">The desired length of the derived key.</param>
    /// <returns>A derived key based on the specified <paramref name="secret"/>.</returns>
    /// <exception cref="CryptographicException">
    /// The implementation resolved from <see cref="CryptoConfig.CreateFromName(string)"/> is not valid.
    /// </exception>
    public static byte[] DeriveKey(string secret, byte[] salt, HashAlgorithmName algorithm, int iterations, int length)
    {
        // Warning: the type and order of the arguments specified here MUST exactly match the parameters used with
        // Rfc2898DeriveBytes(string password, byte[] salt, int iterations, HashAlgorithmName hashAlgorithm).
        using var generator = CryptoConfig.CreateFromName("OpenIddict PBKDF2 Cryptographic Provider",
            args: new object?[] { secret, salt, iterations, algorithm }) switch
        {
            Rfc2898DeriveBytes result => result,

#pragma warning disable CA5379
            null => new Rfc2898DeriveBytes(secret, salt, iterations, algorithm),
#pragma warning restore CA5379

            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        return generator.GetBytes(length);
    }
#endif

#if SUPPORTS_ECDSA
    /// <summary>
    /// Determines whether the specified <paramref name="parameters"/> represent a specific EC curve.
    /// </summary>
    /// <param name="parameters">The <see cref="ECParameters"/>.</param>
    /// <param name="curve">The <see cref="ECCurve"/>.</param>
    /// <returns>
    /// <see langword="true"/> if <see cref="ECParameters.Curve"/> is identical to
    /// the specified <paramref name="curve"/>, <see langword="false"/> otherwise.
    /// </returns>
    public static bool IsEcCurve(ECParameters parameters, ECCurve curve)
    {
        Debug.Assert(parameters.Curve.Oid is not null, SR.GetResourceString(SR.ID4011));
        Debug.Assert(curve.Oid is not null, SR.GetResourceString(SR.ID4011));

        // Warning: on .NET Framework 4.x and .NET Core 2.1, exported ECParameters generally have
        // a null OID value attached. To work around this limitation, both the raw OID values and
        // the friendly names are compared to determine whether the curve is of the specified type.
        if (!string.IsNullOrEmpty(parameters.Curve.Oid.Value) &&
            !string.IsNullOrEmpty(curve.Oid.Value))
        {
            return string.Equals(parameters.Curve.Oid.Value,
                curve.Oid.Value, StringComparison.Ordinal);
        }

        if (!string.IsNullOrEmpty(parameters.Curve.Oid.FriendlyName) &&
            !string.IsNullOrEmpty(curve.Oid.FriendlyName))
        {
            return string.Equals(parameters.Curve.Oid.FriendlyName,
                curve.Oid.FriendlyName, StringComparison.Ordinal);
        }

        Debug.Fail(SR.GetResourceString(SR.ID4012));
        return false;
    }
#endif
}
