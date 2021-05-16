/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using OpenIddict.Abstractions;
using SR = OpenIddict.Abstractions.OpenIddictResources;

#if !SUPPORTS_KEY_DERIVATION_WITH_SPECIFIED_HASH_ALGORITHM
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
#endif

#if !SUPPORTS_TIME_CONSTANT_COMPARISONS
using Org.BouncyCastle.Utilities;
#endif

namespace OpenIddict.Core
{
    public class OpenIddictClientSecretHasher : IOpenIddictClientSecretHasher
    {
        /// <inheritdoc />
        public virtual ValueTask<bool> ValidateClientSecretAsync(
            string secret, string comparand, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0216), nameof(secret));
            }

            if (string.IsNullOrEmpty(comparand))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0218), nameof(comparand));
            }

            return new ValueTask<bool>(VerifyHashedSecret(comparand, secret));

            // Note: the following logic deliberately uses the same format as CryptoHelper (used in OpenIddict 1.x/2.x),
            // which was itself based on ASP.NET Core Identity's latest hashed password format. This guarantees that
            // secrets hashed using a recent OpenIddict version can still be read by older packages (and vice versa).

            static bool VerifyHashedSecret(string hash, string secret)
            {
                var payload = new ReadOnlySpan<byte>(Convert.FromBase64String(hash));
                if (payload.Length == 0)
                {
                    return false;
                }

                // Verify the hashing format version.
                if (payload[0] != 0x01)
                {
                    return false;
                }

                // Read the hashing algorithm version.
                var algorithm = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(1, 4)) switch
                {
                    0 => HashAlgorithmName.SHA1,
                    1 => HashAlgorithmName.SHA256,
                    2 => HashAlgorithmName.SHA512,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0217))
                };

                // Read the iteration count of the algorithm.
                var iterations = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(5, 8));

                // Read the size of the salt and ensure it's more than 128 bits.
                var saltLength = (int)BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(9, 12));
                if (saltLength < 128 / 8)
                {
                    return false;
                }

                // Read the salt.
                var salt = payload.Slice(13, saltLength);

                // Ensure the derived key length is more than 128 bits.
                var keyLength = payload.Length - 13 - salt.Length;
                if (keyLength < 128 / 8)
                {
                    return false;
                }

#if SUPPORTS_TIME_CONSTANT_COMPARISONS
                return CryptographicOperations.FixedTimeEquals(
                    left: payload.Slice(13 + salt.Length, keyLength),
                    right: DeriveKey(secret, salt, algorithm, iterations, keyLength));
#else
                return Arrays.ConstantTimeAreEqual(
                    a: payload.Slice(13 + salt.Length, keyLength).ToArray(),
                    b: DeriveKey(secret, salt, algorithm, iterations, keyLength));
#endif
            }
        }

        /// <inheritdoc />
        public virtual ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0216), nameof(secret));
            }

            // Note: the PRF, iteration count, salt length and key length currently all match the default values
            // used by CryptoHelper and ASP.NET Core Identity but this may change in the future, if necessary.

            var salt = new byte[128 / 8];

#if SUPPORTS_STATIC_RANDOM_NUMBER_GENERATOR_METHODS
            RandomNumberGenerator.Fill(salt);
#else
            using var generator = RandomNumberGenerator.Create();
            generator.GetBytes(salt);
#endif

            var hash = HashSecret(secret, salt, HashAlgorithmName.SHA256, iterations: 10_000, length: 256 / 8);

            return new ValueTask<string>(
#if SUPPORTS_BASE64_SPAN_CONVERSION
                Convert.ToBase64String(hash)
#else
                Convert.ToBase64String(hash.ToArray())
#endif
            );

            // Note: the following logic deliberately uses the same format as CryptoHelper (used in OpenIddict 1.x/2.x),
            // which was itself based on ASP.NET Core Identity's latest hashed password format. This guarantees that
            // secrets hashed using a recent OpenIddict version can still be read by older packages (and vice versa).

            static ReadOnlySpan<byte> HashSecret(string secret, ReadOnlySpan<byte> salt,
                HashAlgorithmName algorithm, int iterations, int length)
            {
                var key = DeriveKey(secret, salt, algorithm, iterations, length);
                var payload = new Span<byte>(new byte[13 + salt.Length + key.Length]);

                // Write the format marker.
                payload[0] = 0x01;

                // Write the hashing algorithm version.
                BinaryPrimitives.WriteUInt32BigEndian(payload.Slice(1, 4), algorithm switch
                {
                    var name when name == HashAlgorithmName.SHA1 => 0,
                    var name when name == HashAlgorithmName.SHA256 => 1,
                    var name when name == HashAlgorithmName.SHA512 => 2,

                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0217))
                });

                // Write the iteration count of the algorithm.
                BinaryPrimitives.WriteUInt32BigEndian(payload.Slice(5, 8), (uint)iterations);

                // Write the size of the salt.
                BinaryPrimitives.WriteUInt32BigEndian(payload.Slice(9, 12), (uint)salt.Length);

                // Write the salt.
                salt.CopyTo(payload.Slice(13));

                // Write the subkey.
                key.CopyTo(payload.Slice(13 + salt.Length));

                return payload;
            }
        }

        [SuppressMessage("Security", "CA5379:Do not use weak key derivation function algorithm",
            Justification = "The SHA-1 digest algorithm is still supported for backward compatibility.")]
        private static byte[] DeriveKey(string secret, ReadOnlySpan<byte> salt,
            HashAlgorithmName algorithm, int iterations, int length)
        {
#if SUPPORTS_KEY_DERIVATION_WITH_SPECIFIED_HASH_ALGORITHM
            using var generator = new Rfc2898DeriveBytes(secret, salt.ToArray(), iterations, algorithm);
            return generator.GetBytes(length);
#else
            var generator = new Pkcs5S2ParametersGenerator(algorithm switch
            {
                var name when name == HashAlgorithmName.SHA1 => new Sha1Digest(),
                var name when name == HashAlgorithmName.SHA256 => new Sha256Digest(),
                var name when name == HashAlgorithmName.SHA512 => new Sha512Digest(),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0217))
            });

            generator.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(secret.ToCharArray()), salt.ToArray(), iterations);

            var key = (KeyParameter)generator.GenerateDerivedMacParameters(length * 8);
            return key.GetKey();
#endif
        }
    }
}
