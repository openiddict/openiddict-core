/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Properties = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties;
using Tokens = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Tokens;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Contains the request delegates used by the OpenIddict backend-for-frontend (BFF) endpoints.
/// </summary>
internal static class OpenIddictClientAspNetCoreBffEndpoints
{
    /// <summary>
    /// Starts an interactive login flow: the user agent is redirected to the authorization server.
    /// </summary>
    public static async Task LoginAsync(HttpContext context)
    {
        var options = OpenIddictClientAspNetCoreBffHelpers.GetOptions(context);

        if (!TryResolveReturnUrl(context, options, context.Request.Query[OpenIddictClientAspNetCoreBffConstants.QueryStringParameters.ReturnUrl],
            out var url))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var properties = new AuthenticationProperties { RedirectUri = url };

        var provider = (string?) context.Request.Query[OpenIddictClientAspNetCoreBffConstants.QueryStringParameters.Provider];
        if (!string.IsNullOrEmpty(provider))
        {
            // Validate the provider name before triggering the challenge to return a 400 response for unknown providers.
            try
            {
                await context.RequestServices.GetRequiredService<OpenIddictClientService>()
                    .GetClientRegistrationByProviderNameAsync(provider, context.RequestAborted);
            }

            catch (InvalidOperationException)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            properties.Items[Properties.ProviderName] = provider;
        }

        await context.ChallengeAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, properties);
    }

    /// <summary>
    /// Handles the login callback: the authorization data is validated and the user is signed in.
    /// </summary>
    public static async Task LoginCallbackAsync(HttpContext context)
    {
        var options = OpenIddictClientAspNetCoreBffHelpers.GetOptions(context);

        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
        if (result is not { Succeeded: true, Principal: ClaimsPrincipal principal, Properties: AuthenticationProperties ticket })
        {
            await WriteErrorAsync(context,
                GetItem(result.Properties, Properties.Error) ?? Errors.InvalidRequest,
                GetItem(result.Properties, Properties.ErrorDescription));

            return;
        }

        // Note: authorization servers that don't support OpenID Connect may not return any user claim, in which case
        // the identity is not authenticated: an authentication type is always set to allow creating a session.
        var identity = new ClaimsIdentity(principal.Claims,
            authenticationType: principal.Identity?.AuthenticationType is { Length: > 0 } type ? type : OpenIddictClientAspNetCoreDefaults.AuthenticationScheme,
            nameType: (principal.Identity as ClaimsIdentity)?.NameClaimType ?? Claims.Name,
            roleType: (principal.Identity as ClaimsIdentity)?.RoleClaimType ?? Claims.Role);

        var properties = new AuthenticationProperties
        {
            // Decorrelate the lifetime of the session from the lifetime of the state token.
            ExpiresUtc = null,
            IsPersistent = false,
            IssuedUtc = null
        };

        foreach (var name in (ReadOnlySpan<string>) [Properties.Issuer, Properties.ProviderName, Properties.RegistrationId])
        {
            if (GetItem(ticket, name) is string value)
            {
                properties.Items[name] = value;
            }
        }

        // Only store the tokens required by the BFF components to limit the size of the ticket.
        properties.StoreTokens(ticket.GetTokens().Where(static token => token.Name is
            Tokens.BackchannelAccessToken               or
            Tokens.BackchannelAccessTokenExpirationDate or
            Tokens.BackchannelAccessTokenType           or
            Tokens.BackchannelIdentityToken             or
            Tokens.RefreshToken));

        await context.SignInAsync(options.CookieScheme, new ClaimsPrincipal(identity), properties);

        context.Response.Redirect(TryResolveReturnUrl(context, options, ticket.RedirectUri, out var url) && url is not null
            ? url : ResolveUrl(context, options.DefaultReturnUrl));
    }

    /// <summary>
    /// Removes the local session and, if supported by the authorization server, starts an end session flow.
    /// </summary>
    public static async Task LogoutAsync(HttpContext context)
    {
        var options = OpenIddictClientAspNetCoreBffHelpers.GetOptions(context);

        if (!TryResolveReturnUrl(context, options, context.Request.Query[OpenIddictClientAspNetCoreBffConstants.QueryStringParameters.ReturnUrl],
            out var url))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var result = await context.AuthenticateAsync(options.CookieScheme);
        if (result is not { Succeeded: true, Principal: ClaimsPrincipal principal })
        {
            context.Response.Redirect(url);
            return;
        }

        // To mitigate logout CSRF attacks, the session identifier must be specified when the session has one.
        var session = principal.FindFirst(Claims.SessionId)?.Value;
        if (!string.IsNullOrEmpty(session) && !string.Equals(session, context.Request.Query[
            OpenIddictClientAspNetCoreBffConstants.QueryStringParameters.SessionId], StringComparison.Ordinal))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        await context.SignOutAsync(options.CookieScheme);

        var registration = OpenIddictClientAspNetCoreBffTokenManager.GetRegistrationId(principal, result.Properties);
        if (!string.IsNullOrEmpty(registration))
        {
            var service = context.RequestServices.GetRequiredService<OpenIddictClientService>();

            var configuration = await service.GetServerConfigurationByRegistrationIdAsync(registration, context.RequestAborted);
            if (configuration.EndSessionEndpoint is not null)
            {
                var properties = new AuthenticationProperties(new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    [Properties.RegistrationId] = registration,
                    [Properties.IdentityTokenHint] = result.Properties?.GetTokenValue(Tokens.BackchannelIdentityToken)
                })
                {
                    RedirectUri = url
                };

                await context.SignOutAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme, properties);
                return;
            }
        }

        context.Response.Redirect(url);
    }

    /// <summary>
    /// Handles the logout callback: the user agent is redirected to the return URL.
    /// </summary>
    public static async Task LogoutCallbackAsync(HttpContext context)
    {
        var options = OpenIddictClientAspNetCoreBffHelpers.GetOptions(context);

        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

        context.Response.Redirect(TryResolveReturnUrl(context, options, result.Properties?.RedirectUri, out var url) && url is not null
            ? url : ResolveUrl(context, options.DefaultReturnUrl));
    }

    /// <summary>
    /// Returns the claims of the authenticated user (the antiforgery header is required).
    /// </summary>
    public static async Task UserAsync(HttpContext context)
    {
        var options = OpenIddictClientAspNetCoreBffHelpers.GetOptions(context);

        SetNoCacheHeaders(context);

        if (!context.HasValidAntiforgeryHeader())
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var result = await context.AuthenticateAsync(options.CookieScheme);
        if (result is not { Succeeded: true, Principal: ClaimsPrincipal principal })
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var url = context.Request.PathBase.Add(options.LogoutPath).Value!;
        if (principal.FindFirst(Claims.SessionId)?.Value is { Length: > 0 } session)
        {
            url = QueryHelpers.AddQueryString(url, OpenIddictClientAspNetCoreBffConstants.QueryStringParameters.SessionId, session);
        }

        context.Response.ContentType = "application/json;charset=UTF-8";

        await using var writer = new Utf8JsonWriter(context.Response.Body);

        writer.WriteStartArray();

        foreach (var claim in principal.Claims)
        {
            WriteClaim(writer, claim.Type, claim.Value);
        }

        if (result.Properties?.ExpiresUtc is DateTimeOffset date)
        {
            var provider = context.RequestServices.GetService<Microsoft.Extensions.Options.IOptionsMonitor<OpenIddictClientOptions>>()
                ?.CurrentValue.TimeProvider ?? TimeProvider.System;

            WriteClaim(writer, OpenIddictClientAspNetCoreBffConstants.Claims.SessionExpiresIn,
                Math.Max(0, (long) (date - provider.GetUtcNow()).TotalSeconds).ToString(CultureInfo.InvariantCulture));
        }

        WriteClaim(writer, OpenIddictClientAspNetCoreBffConstants.Claims.LogoutUrl, url);

        writer.WriteEndArray();

        await writer.FlushAsync(context.RequestAborted);

        static void WriteClaim(Utf8JsonWriter writer, string type, string value)
        {
            writer.WriteStartObject();
            writer.WriteString("type", type);
            writer.WriteString("value", value);
            writer.WriteEndObject();
        }
    }

    /// <summary>
    /// Handles back-channel logout notifications sent by authorization servers.
    /// </summary>
    public static async Task BackchannelLogoutAsync(HttpContext context)
    {
        SetNoCacheHeaders(context);

        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasFormContentType)
        {
            await WriteErrorAsync(context, Errors.InvalidRequest, SR.GetResourceString(SR.ID2239));
            return;
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted);

        var token = (string?) form[Parameters.LogoutToken];
        if (string.IsNullOrEmpty(token))
        {
            await WriteErrorAsync(context, Errors.InvalidRequest, SR.GetResourceString(SR.ID2239));
            return;
        }

        var validator = context.RequestServices.GetService<OpenIddictClientAspNetCoreBffLogoutTokenValidator>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0561));

        var notification = await validator.ValidateAsync(context, token);
        if (notification is null)
        {
            await WriteErrorAsync(context, Errors.InvalidRequest, SR.GetResourceString(SR.ID2240));
            return;
        }

        foreach (var handler in context.RequestServices.GetServices<IOpenIddictClientAspNetCoreBffBackchannelLogoutHandler>())
        {
            await handler.HandleAsync(notification, context.RequestAborted);
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
    }

    private static string? GetItem(AuthenticationProperties? properties, string name)
        => properties?.Items.TryGetValue(name, out var value) is true && !string.IsNullOrEmpty(value) ? value : null;

    private static void SetNoCacheHeaders(HttpContext context)
    {
        context.Response.Headers[OpenIddictClientAspNetCoreBffConstants.Headers.CacheControl] = "no-store";
        context.Response.Headers[OpenIddictClientAspNetCoreBffConstants.Headers.Pragma] = "no-cache";
    }

    private static string ResolveUrl(HttpContext context, string url)
        => url.StartsWith("~/", StringComparison.Ordinal) ? context.Request.PathBase.Add(url[1..]).Value! : url;

    private static bool TryResolveReturnUrl(HttpContext context,
        OpenIddictClientAspNetCoreBffOptions options, string? value, out string url)
    {
        if (string.IsNullOrEmpty(value))
        {
            url = ResolveUrl(context, options.DefaultReturnUrl);
            return true;
        }

        // Only allow local return URLs to prevent open redirect attacks.
        if (!OpenIddictClientAspNetCoreBffHelpers.IsLocalUrl(value))
        {
            url = string.Empty;
            return false;
        }

        url = ResolveUrl(context, value);
        return true;
    }

    private static async Task WriteErrorAsync(HttpContext context, string error, string? description)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json;charset=UTF-8";

        await using var writer = new Utf8JsonWriter(context.Response.Body);

        writer.WriteStartObject();
        writer.WriteString(Parameters.Error, error);

        if (!string.IsNullOrEmpty(description))
        {
            writer.WriteString(Parameters.ErrorDescription, description);
        }

        writer.WriteEndObject();

        await writer.FlushAsync(context.RequestAborted);
    }
}
