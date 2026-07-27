/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Extensions;

/// <summary>
/// Exposes common polyfills used by the OpenIddict assemblies.
/// </summary>
internal static class OpenIddictPolyfills
{
    extension(CryptographicOperations)
    {
#if !NET
        /// <summary>
        /// Determine the equality of two byte sequences in an amount of time which depends on
        /// the length of the sequences, but not the values.
        /// </summary>
        /// <param name="left">The first buffer to compare.</param>
        /// <param name="right">The second buffer to compare.</param>
        /// <returns>
        ///   <c>true</c> if <paramref name="left"/> and <paramref name="right"/> have the same
        ///   values for <see cref="ReadOnlySpan{T}.Length"/> and the same contents, <c>false</c>
        ///   otherwise.
        /// </returns>
        /// <remarks>
        ///   This method compares two buffers' contents for equality in a manner which does not
        ///   leak timing information, making it ideal for use within cryptographic routines.
        ///   This method will short-circuit and return <c>false</c> only if <paramref name="left"/>
        ///   and <paramref name="right"/> have different lengths.
        ///
        ///   Fixed-time behavior is guaranteed in all other cases, including if <paramref name="left"/>
        ///   and <paramref name="right"/> reference the same address.
        /// </remarks>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            // Note: the logic used here is directly taken from the official implementation of
            // the CryptographicOperations.FixedTimeEquals() method introduced in .NET Core 2.1.
            //
            // See https://github.com/dotnet/corefx/pull/27103 for more information.

            // Note: these null checks can be theoretically considered as early checks
            // (which would defeat the purpose of a time-constant comparison method),
            // but the expected string length is the only information an attacker
            // could get at this stage, which is not critical where this method is used.

            if (left.Length != right.Length)
            {
                return false;
            }

            var length = left.Length;
            var accumulator = 0;

            for (var index = 0; index < length; index++)
            {
                accumulator |= left[index] - right[index];
            }

            return accumulator is 0;
        }
#endif
    }

    extension(HMACSHA256)
    {
#if !NET
        /// <summary>
        /// Computes the HMAC of data using the SHA256 algorithm.
        /// </summary>
        /// <param name="key">The HMAC key.</param>
        /// <param name="source">The data to HMAC.</param>
        /// <returns>The HMAC of the data.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="key" /> or <paramref name="source" /> is <see langword="null" />.
        /// </exception>
        public static byte[] HashData(byte[] key, byte[] source)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(source);

            using var algorithm = new HMACSHA256(key);
            return algorithm.ComputeHash(source);
        }
#endif
    }

    extension(OperatingSystem)
    {
#if !NET
        /// <summary>
        /// Indicates whether the current application is running on Android.
        /// </summary>
        public static bool IsAndroid() => RuntimeInformation.IsOSPlatform(OSPlatform.Create("ANDROID"));

        /// <summary>
        /// Check for the Android API level (returned by 'ro.build.version.sdk') with a >=
        /// version comparison. Used to guard APIs that were added in the given Android release.
        /// </summary>
        public static bool IsAndroidVersionAtLeast(int major, int minor = 0, int build = 0, int revision = 0)
            => IsAndroid() && IsOSVersionAtLeast(major, minor, build, revision);

        /// <summary>
        /// Indicates whether the current application is running on iOS or MacCatalyst.
        /// </summary>
        [SupportedOSPlatformGuard("maccatalyst")]
        public static bool IsIOS() => RuntimeInformation.IsOSPlatform(OSPlatform.Create("IOS"));

        /// <summary>
        /// Check for the iOS/MacCatalyst version (returned by 'libobjc.get_operatingSystemVersion')
        /// with a >= version comparison. Used to guard APIs that were added in the given iOS release.
        /// </summary>
        [SupportedOSPlatformGuard("maccatalyst")]
        public static bool IsIOSVersionAtLeast(int major, int minor = 0, int build = 0)
            => IsIOS() && IsOSVersionAtLeast(major, minor, build, 0);

        /// <summary>
        /// Indicates whether the current application is running on Linux.
        /// </summary>
        public static bool IsLinux() => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        /// <summary>
        /// Indicates whether the current application is running on Mac Catalyst.
        /// </summary>
        public static bool IsMacCatalyst() => RuntimeInformation.IsOSPlatform(OSPlatform.Create("MACCATALYST"));

        /// <summary>
        /// Check for the Mac Catalyst version (iOS version as presented in Apple documentation) with a >=
        /// version comparison. Used to guard APIs that were added in the given Mac Catalyst release.
        /// </summary>
        public static bool IsMacCatalystVersionAtLeast(int major, int minor = 0, int build = 0)
            => IsMacCatalyst() && IsOSVersionAtLeast(major, minor, build, 0);

        /// <summary>
        /// Indicates whether the current application is running on macOS.
        /// </summary>
        public static bool IsMacOS() => RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        /// <summary>
        /// Check for the macOS version (returned by 'libobjc.get_operatingSystemVersion') with a >=
        /// version comparison. Used to guard APIs that were added in the given macOS release.
        /// </summary>
        public static bool IsMacOSVersionAtLeast(int major, int minor = 0, int build = 0)
            => IsMacOS() && IsOSVersionAtLeast(major, minor, build, 0);

        /// <summary>
        /// Indicates whether the current application is running on Windows.
        /// </summary>
        public static bool IsWindows() => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

        /// <summary>
        /// Check for the Windows version (returned by 'RtlGetVersion') with a >= version
        /// comparison. Used to guard APIs that were added in the given Windows release.
        /// </summary>
        public static bool IsWindowsVersionAtLeast(int major, int minor = 0, int build = 0, int revision = 0)
        {
            if (Environment.OSVersion.Platform is PlatformID.Win32NT &&
                Environment.OSVersion.Version >= new Version(major, minor, build, revision))
            {
                return true;
            }

            // Note: on older versions of .NET, Environment.OSVersion.Version is known to be affected by
            // the compatibility shims used by Windows 10+ when the application doesn't have a manifest
            // that explicitly indicates it's compatible with Windows 10 and higher. To avoid that, a
            // second pass using RuntimeInformation.OSDescription (that calls NtDll.RtlGetVersion() under
            // the hood) is made. Note: no version is returned on UWP due to the missing Win32 API.
            return RuntimeInformation.OSDescription.StartsWith("Microsoft Windows ", StringComparison.OrdinalIgnoreCase) &&
                   RuntimeInformation.OSDescription["Microsoft Windows ".Length..] is string value &&
                   Version.TryParse(value, out Version? version) && version >= new Version(major, minor, build, revision);
        }
#endif
    }

    extension(Rfc2898DeriveBytes)
    {
#if !NET
        /// <summary>
        /// Creates a PBKDF2 derived key from a password.
        /// </summary>
        /// <param name="password">The password used to derive the key.</param>
        /// <param name="salt">The key salt used to derive the key.</param>
        /// <param name="iterations">The number of iterations for the operation.</param>
        /// <param name="hashAlgorithm">The hash algorithm to use to derive the key.</param>
        /// <param name="outputLength">The size of key to derive.</param>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <para><paramref name="outputLength" /> is not zero or a positive value.</para>
        ///   <para>-or-</para>
        ///   <para><paramref name="iterations" /> is not a positive value.</para>
        /// </exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="hashAlgorithm" /> has a <see cref="HashAlgorithmName.Name" />
        ///   that is empty or <see langword="null" />.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   <paramref name="hashAlgorithm" /> is an unsupported hash algorithm. Supported algorithms
        ///   are <see cref="HashAlgorithmName.SHA1" />, <see cref="HashAlgorithmName.SHA256" />,
        ///   <see cref="HashAlgorithmName.SHA384" />, and <see cref="HashAlgorithmName.SHA512" />.
        /// </exception>
        public static byte[] Pbkdf2(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> salt,
            int iterations,
            HashAlgorithmName hashAlgorithm,
            int outputLength)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(outputLength);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(iterations);

            using var algorithm = new Rfc2898DeriveBytes(password.ToString(), salt.ToArray(), iterations, hashAlgorithm);
            return algorithm.GetBytes(outputLength);
        }
#endif
    }

    extension<TResult>(ValueTask<TResult>)
    {
#if !NET
        /// <summary>
        /// Gets a task that has already completed successfully.
        /// </summary>
        public static ValueTask<TResult> CompletedTask => default;
#endif
    }

#if !NET
    static bool IsOSVersionAtLeast(int major, int minor, int build, int revision)
    {
        Version current = Environment.OSVersion.Version;

        if (current.Major != major)
        {
            return current.Major > major;
        }
        if (current.Minor != minor)
        {
            return current.Minor > minor;
        }

        int currentBuild = current.Build < 0 ? 0 : current.Build;
        build = build < 0 ? 0 : build;
        if (currentBuild != build)
        {
            return currentBuild > build;
        }

        int currentRevision = current.Revision < 0 ? 0 : current.Revision;
        revision = revision < 0 ? 0 : revision;

        return currentRevision >= revision;
    }
#endif

    extension(X509ChainPolicy policy)
    {
#if !NET
        public X509ChainPolicy Clone()
        {
            var clone = new X509ChainPolicy
            {
                RevocationMode = policy.RevocationMode,
                RevocationFlag = policy.RevocationFlag,
                UrlRetrievalTimeout = policy.UrlRetrievalTimeout,
                VerificationFlags = policy.VerificationFlags,
                VerificationTime = policy.VerificationTime,
#if NET
                DisableCertificateDownloads = policy.DisableCertificateDownloads,
                TrustMode = policy.TrustMode,
                VerificationTimeIgnored = policy.VerificationTimeIgnored
#endif
            };

            if (policy.ApplicationPolicy.Count is > 0)
            {
                for (var index = 0; index < policy.ApplicationPolicy.Count; index++)
                {
                    clone.ApplicationPolicy.Add(policy.ApplicationPolicy[index]);
                }
            }

            if (policy.CertificatePolicy.Count is > 0)
            {
                for (var index = 0; index < policy.CertificatePolicy.Count; index++)
                {
                    clone.CertificatePolicy.Add(policy.CertificatePolicy[index]);
                }
            }

#if NET
            clone.CustomTrustStore.AddRange(policy.CustomTrustStore);
#endif

            clone.ExtraStore.AddRange(policy.ExtraStore);

            return clone;
        }
#endif
    }
}
