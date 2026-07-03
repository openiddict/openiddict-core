/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Validation.SystemNetHttp;

/// <summary>
/// Represents the context used by the System.Net.Http integration when creating a new HTTP client.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictValidationSystemNetHttpContext
{
    private static readonly AsyncLocal<OpenIddictValidationSystemNetHttpContext?> _current = new();

    /// <summary>
    /// Gets or sets the X.509 client certificate that will be used to authenticate
    /// this peer when communicating with the external endpoint, if applicable.
    /// </summary>
    public X509Certificate2? LocalCertificate { get; init; }

    /// <summary>
    /// Gets or sets the ambient context for the current execution flow.
    /// </summary>
    public static OpenIddictValidationSystemNetHttpContext? Current
    {
        get => _current.Value;
        set => _current.Value = value;
    }

    /// <summary>
    /// Computes a stable, unique identifier for the specified context using a cryptographic hash.
    /// </summary>
    /// <param name="context">The client context for which to compute the stable identifier.</param>
    /// <returns>A string representing the stable identifier for the specified context.</returns>
    public static string ComputeStableId(OpenIddictValidationSystemNetHttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        using var algorithm = SHA256.Create();

        if (context.LocalCertificate is X509Certificate2 certificate)
        {
            algorithm.TransformBlock(certificate.RawData, 0, certificate.RawData.Length, outputBuffer: null, outputOffset: 0);
        }

        algorithm.TransformFinalBlock([], 0, 0);

        return Base64Url.EncodeToString(algorithm.Hash);
    }
}
