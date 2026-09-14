/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Server.AspNetCore.AdminUI;

/// <summary>
/// Exposes common constants used by the OpenIddict admin UI.
/// </summary>
public static class OpenIddictServerAspNetCoreAdminUIConstants
{
    /// <summary>
    /// Default route prefix used by the OpenIddict admin UI pages.
    /// </summary>
    public const string DefaultRoutePrefix = "/openiddict/admin";

    public static class Paths
    {
        public const string Applications = "applications";
        public const string Authorizations = "authorizations";
        public const string Delete = "delete";
        public const string Keys = "keys";
        public const string New = "new";
        public const string Revoke = "revoke";
        public const string Scopes = "scopes";
        public const string Secret = "secret";
        public const string Stylesheet = "openiddict-admin.css";
        public const string Tokens = "tokens";
    }

    public static class FormFields
    {
        public const string AdditionalPermissions = "additional_permissions";
        public const string AdditionalRequirements = "additional_requirements";
        public const string ApplicationType = "application_type";
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string ClientType = "client_type";
        public const string ConsentType = "consent_type";
        public const string Description = "description";
        public const string DisplayName = "display_name";
        public const string JsonWebKeySet = "json_web_key_set";
        public const string Mode = "mode";
        public const string Name = "name";
        public const string Permissions = "permissions";
        public const string PostLogoutRedirectUris = "post_logout_redirect_uris";
        public const string RedirectUris = "redirect_uris";
        public const string RemoveJsonWebKeySet = "remove_json_web_key_set";
        public const string Requirements = "requirements";
        public const string Resources = "resources";
        public const string Settings = "settings";
    }

    public static class QueryStringParameters
    {
        public const string Authorization = "authorization";
        public const string Client = "client";
        public const string Notice = "notice";
        public const string Page = "page";
        public const string Search = "search";
        public const string Status = "status";
        public const string Subject = "subject";
        public const string Type = "type";
    }

    public static class SecretModes
    {
        public const string Generate = "generate";
        public const string Remove = "remove";
        public const string Set = "set";
    }

    public static class Notices
    {
        public const string Created = "created";
        public const string Deleted = "deleted";
        public const string Revoked = "revoked";
        public const string Updated = "updated";
    }
}
