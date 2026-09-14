/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Sockets;

namespace OpenIddict.Server.SystemNetHttp;

/// <summary>
/// Exposes helpers used by the OpenIddict server/System.Net.Http integration.
/// </summary>
public static class OpenIddictServerSystemNetHttpHelpers
{
    /// <summary>
    /// Determines whether the specified address is a public unicast address, i.e an address that is not part of
    /// the unspecified, loopback, private (RFC 1918, RFC 4193), shared (RFC 6598), link-local (RFC 3927, RFC 4291),
    /// documentation (RFC 5737, RFC 3849), benchmarking (RFC 2544), multicast or reserved ranges (RFC 6890).
    /// </summary>
    /// <param name="address">The IP address.</param>
    /// <returns><see langword="true"/> if the address is a public unicast address, <see langword="false"/> otherwise.</returns>
    public static bool IsPublicAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var bytes = address.GetAddressBytes();

        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => IsPublicIPv4Address(bytes.AsSpan()),
            AddressFamily.InterNetworkV6 => IsPublicIPv6Address(bytes),
            _ => false
        };

        static bool IsPublicIPv4Address(ReadOnlySpan<byte> bytes) => bytes switch
        {
            [0, ..]                           => false, // 0.0.0.0/8 ("this" network)
            [10, ..]                          => false, // 10.0.0.0/8 (private)
            [100, >= 64 and <= 127, ..]       => false, // 100.64.0.0/10 (shared address space)
            [127, ..]                         => false, // 127.0.0.0/8 (loopback)
            [169, 254, ..]                    => false, // 169.254.0.0/16 (link-local)
            [172, >= 16 and <= 31, ..]        => false, // 172.16.0.0/12 (private)
            [192, 0, 0, _]                    => false, // 192.0.0.0/24 (IETF protocol assignments)
            [192, 0, 2, _]                    => false, // 192.0.2.0/24 (documentation)
            [192, 88, 99, _]                  => false, // 192.88.99.0/24 (6to4 relay anycast)
            [192, 168, ..]                    => false, // 192.168.0.0/16 (private)
            [198, 18 or 19, ..]               => false, // 198.18.0.0/15 (benchmarking)
            [198, 51, 100, _]                 => false, // 198.51.100.0/24 (documentation)
            [203, 0, 113, _]                  => false, // 203.0.113.0/24 (documentation)
            [>= 224, ..]                      => false, // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved, broadcast)

            _ => true
        };

        static bool IsPublicIPv6Address(byte[] bytes)
        {
            // ::/96 (unspecified, loopback and deprecated IPv4-compatible addresses).
            var zero = true;

            for (var index = 0; index < 12; index++)
            {
                zero &= bytes[index] is 0;
            }

            if (zero)
            {
                return false;
            }

            return bytes switch
            {
                [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, ..] => IsPublicIPv4Address(bytes.AsSpan(12, 4)), // 64:ff9b::/96 (NAT64)
                [0x20, 0x02, ..]                                   => IsPublicIPv4Address(bytes.AsSpan(2, 4)), // 2002::/16 (6to4)
                [0x20, 0x01, 0x00, 0x00, ..]                       => false, // 2001::/32 (Teredo)
                [0x20, 0x01, 0x0d, 0xb8, ..]                       => false, // 2001:db8::/32 (documentation)
                [0x01, 0x00, 0, 0, 0, 0, 0, 0, ..]                 => false, // 100::/64 (discard-only)
                [>= 0xfc and <= 0xfd, ..]                          => false, // fc00::/7 (unique local)
                [0xfe, >= 0x80, ..]                                => false, // fe80::/10 (link-local) and fec0::/10 (site-local)
                [0xff, ..]                                         => false, // ff00::/8 (multicast)

                _ => true
            };
        }
    }
}
