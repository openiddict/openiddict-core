/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client.SystemNetHttp;

/// <summary>
/// Represents the context used by the System.Net.Http integration when creating a new HTTP client.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientSystemNetHttpContext
{
    private static readonly AsyncLocal<OpenIddictClientSystemNetHttpContext?> _current = new();

    /// <summary>
    /// Gets or sets the X.509 client certificate that will be used to authenticate
    /// this peer when communicating with the external endpoint, if applicable.
    /// </summary>
    public X509Certificate2? LocalCertificate { get; init; }

    /// <summary>
    /// Gets or sets the ambient context for the current execution flow.
    /// </summary>
    public static OpenIddictClientSystemNetHttpContext? Current
    {
        get => _current.Value;
        set => _current.Value = value;
    }

    /// <summary>
    /// Gets or sets the client registration associated with the HTTP client being created.
    /// </summary>
    public required OpenIddictClientRegistration Registration { get; init; }

    /// <summary>
    /// Computes a stable, unique identifier for the specified context using a cryptographic hash.
    /// </summary>
    /// <param name="context">The client context for which to compute the stable identifier.</param>
    /// <returns>A string representing the stable identifier for the specified context.</returns>
    public static string ComputeStableId(OpenIddictClientSystemNetHttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        using var algorithm = CreateAlgorithm();

        TransformBlock(algorithm, context.Registration.RegistrationId!);

        if (context.LocalCertificate is X509Certificate2 certificate)
        {
            algorithm.TransformBlock(certificate.RawData, 0, certificate.RawData.Length, outputBuffer: null, outputOffset: 0);
        }

        algorithm.TransformFinalBlock([], 0, 0);

        return Base64UrlEncoder.Encode(algorithm.Hash);

        [UnconditionalSuppressMessage("Trimming", "IL2026",
            Justification = "The default implementation is always used when no custom algorithm was registered.")]
        static SHA256 CreateAlgorithm() => CryptoConfig.CreateFromName("OpenIddict SHA-256 Cryptographic Provider") switch
        {
            SHA256 result => result,
            null => SHA256.Create(),
            var result => throw new CryptographicException(SR.FormatID0351(result.GetType().FullName))
        };

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        static void TransformBlock(HashAlgorithm algorithm, string input)
        {
            var buffer = Encoding.UTF8.GetBytes(input);
            algorithm.TransformBlock(buffer, 0, buffer.Length, outputBuffer: null, outputOffset: 0);
        }
    }
}
