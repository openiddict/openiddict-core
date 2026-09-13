/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace OpenIddict.Server.Saml.AspNetCore;

/// <summary>
/// Protects the state of validated SAML requests while the user is being authenticated.
/// </summary>
public sealed class OpenIddictServerSamlAspNetCoreStateProtector
{
    private const byte Version = 1;

    private readonly ITimeLimitedDataProtector _protector;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlAspNetCoreStateProtector"/> class.
    /// </summary>
    /// <param name="provider">The data protection provider.</param>
    public OpenIddictServerSamlAspNetCoreStateProtector(IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(provider);

        _protector = provider.CreateProtector("OpenIddict.Server.Saml.AspNetCore.RequestState.v1").ToTimeLimitedDataProtector();
    }

    /// <summary>
    /// Protects the specified state.
    /// </summary>
    /// <param name="state">The state.</param>
    /// <param name="lifetime">The lifetime of the protected payload.</param>
    /// <returns>The protected state, encoded using base64url.</returns>
    public string Protect(RequestState state, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(state);

        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(Version);
            writer.Write(state.ServiceProvider);
            writer.Write(state.AssertionConsumerServiceUrl.AbsoluteUri);
            WriteNullable(writer, state.RequestId);
            WriteNullable(writer, state.RelayState);
            writer.Write(state.ForceAuthentication);
            writer.Write(state.CreationDate.UtcTicks);
        }

        return Base64Url.EncodeToString(_protector.Protect(stream.ToArray(), DateTimeOffset.UtcNow + lifetime));

        static void WriteNullable(BinaryWriter writer, string? value)
        {
            writer.Write(value is not null);
            if (value is not null)
            {
                writer.Write(value);
            }
        }
    }

    /// <summary>
    /// Unprotects the specified state.
    /// </summary>
    /// <param name="value">The protected state.</param>
    /// <returns>The state, or <see langword="null"/> if it is invalid or expired.</returns>
    public RequestState? Unprotect(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            using var stream = new MemoryStream(_protector.Unprotect(Base64Url.DecodeFromChars(value), out _));
            using var reader = new BinaryReader(stream, Encoding.UTF8);

            if (reader.ReadByte() is not Version)
            {
                return null;
            }

            var state = new RequestState
            {
                ServiceProvider = reader.ReadString(),
                AssertionConsumerServiceUrl = new Uri(reader.ReadString(), UriKind.Absolute),
                RequestId = ReadNullable(reader),
                RelayState = ReadNullable(reader),
                ForceAuthentication = reader.ReadBoolean(),
                CreationDate = new DateTimeOffset(reader.ReadInt64(), TimeSpan.Zero)
            };

            return stream.Position == stream.Length ? state : null;
        }

        catch (Exception exception) when (exception is CryptographicException or FormatException or
            EndOfStreamException or IOException or ArgumentException or UriFormatException)
        {
            return null;
        }

        static string? ReadNullable(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;
    }

    /// <summary>
    /// Represents the state of a validated SAML request.
    /// </summary>
    public sealed record class RequestState
    {
        /// <summary>
        /// Gets the entity identifier of the service provider.
        /// </summary>
        public required string ServiceProvider { get; init; }

        /// <summary>
        /// Gets the validated assertion consumer service URL.
        /// </summary>
        public required Uri AssertionConsumerServiceUrl { get; init; }

        /// <summary>
        /// Gets the identifier of the request, or <see langword="null"/> for unsolicited responses.
        /// </summary>
        public string? RequestId { get; init; }

        /// <summary>
        /// Gets the relay state, if any.
        /// </summary>
        public string? RelayState { get; init; }

        /// <summary>
        /// Gets a boolean indicating whether the user must be authenticated after <see cref="CreationDate"/>.
        /// </summary>
        public bool ForceAuthentication { get; init; }

        /// <summary>
        /// Gets the date at which the request was validated.
        /// </summary>
        public required DateTimeOffset CreationDate { get; init; }
    }
}
