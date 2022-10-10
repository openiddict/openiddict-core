/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Validation.SystemNetHttp;

/// <summary>
/// Exposes common constants used by the OpenIddict System.Net.Http integration.
/// </summary>
public static class OpenIddictValidationSystemNetHttpConstants
{
    public static class Charsets
    {
        public const string Utf8 = "utf-8";
    }

    public static class ContentEncodings
    {
        public const string Brotli = "br";
        public const string Deflate = "deflate";
        public const string Gzip = "gzip";
        public const string Identity = "identity";
    }

    public static class MediaTypes
    {
        public const string Json = "application/json";
    }
}
