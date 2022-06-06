/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Client.DataProtection;

public static class OpenIddictClientDataProtectionConstants
{
    public static class Properties
    {
        public const string Audiences = ".audiences";
        public const string CodeVerifier = ".code_verifier";
        public const string Expires = ".expires";
        public const string HostProperties = ".host_properties";
        public const string InternalTokenId = ".internal_token_id";
        public const string Issued = ".issued";
        public const string Nonce = ".nonce";
        public const string OriginalRedirectUri = ".original_redirect_uri";
        public const string Presenters = ".presenters";
        public const string Resources = ".resources";
        public const string Scopes = ".scopes";
        public const string StateTokenLifetime = ".state_token_lifetime";
    }

    public static class Purposes
    {
        public static class Features
        {
            public const string ReferenceTokens = "UseReferenceTokens";
        }

        public static class Formats
        {
            public const string StateToken = "StateTokenFormat";
        }

        public static class Handlers
        {
            public const string Client = "OpenIdConnectClientHandler";
        }

        public static class Schemes
        {
            public const string Server = "ASOC";
        }
    }
}
