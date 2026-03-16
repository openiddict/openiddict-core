/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace OpenIddict.Extensions;

/// <summary>
/// Exposes common polyfills used by the OpenIddict assemblies.
/// </summary>
internal static class OpenIddictPolyfills
{
    extension(Convert)
    {
#if !SUPPORTS_HEXADECIMAL_STRING_CONVERSION

        /// <summary>Converts the specified string, which encodes binary data as hex characters, to an equivalent 8-bit unsigned integer array.</summary>
        /// <param name="s">The string to convert.</param>
        /// <returns>An array of 8-bit unsigned integers that is equivalent to <paramref name="s"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="s"/> is <code>null</code>.</exception>
        /// <exception cref="FormatException">The length of <paramref name="s"/>, is not zero or a multiple of 2.</exception>
        /// <exception cref="FormatException">The format of <paramref name="s"/> is invalid. <paramref name="s"/> contains a non-hex character.</exception>
        public static byte[] FromHexString(string s)
        {
            if ((uint) s.Length % 2 is not 0)
            {
                throw new FormatException(SR.GetResourceString(SR.ID0413));
            }

            var array = new byte[s.Length / 2];

            for (var index = 0; index < s.Length; index += 2)
            {
                array[index / 2] = Convert.ToByte(s.Substring(index, 2), 16);
            }

            return array;
        }
#endif
    }

    extension(OperatingSystem)
    {
#if !SUPPORTS_OPERATING_SYSTEM_VERSIONS_COMPARISON
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

    extension<TResult>(ValueTask<TResult>)
    {
#if !SUPPORTS_VALUETASK_COMPLETED_TASK
        /// <summary>
        /// Gets a task that has already completed successfully.
        /// </summary>
        public static ValueTask<TResult> CompletedTask => default;
#endif
    }

#if !SUPPORTS_OPERATING_SYSTEM_VERSIONS_COMPARISON
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
#if !SUPPORTS_X509_CHAIN_POLICY_CLONING
        public X509ChainPolicy Clone()
        {
            var clone = new X509ChainPolicy
            {
#if SUPPORTS_X509_CHAIN_POLICY_DOWNLOAD_MODE
                DisableCertificateDownloads = policy.DisableCertificateDownloads,
#endif
                RevocationMode = policy.RevocationMode,
                RevocationFlag = policy.RevocationFlag,
#if SUPPORTS_X509_CHAIN_POLICY_TRUST_MODE
                TrustMode = policy.TrustMode,
#endif
                UrlRetrievalTimeout = policy.UrlRetrievalTimeout,
                VerificationFlags = policy.VerificationFlags,
                VerificationTime = policy.VerificationTime,
#if SUPPORTS_X509_CHAIN_POLICY_VERIFICATION_TIME_MODE
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

#if SUPPORTS_X509_CHAIN_POLICY_CUSTOM_TRUST_STORE
            clone.CustomTrustStore.AddRange(policy.CustomTrustStore);
#endif

            clone.ExtraStore.AddRange(policy.ExtraStore);

            return clone;
        }
#endif
    }
}
