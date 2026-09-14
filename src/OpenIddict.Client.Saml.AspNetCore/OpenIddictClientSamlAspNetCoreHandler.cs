/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Client.Saml.OpenIddictClientSamlConstants;
using static OpenIddict.Client.Saml.OpenIddictClientSamlModels;
using Parameters = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Parameters;
using Properties = OpenIddict.Client.Saml.OpenIddictClientSamlConstants.Properties;
using StatusCodes = Microsoft.AspNetCore.Http.StatusCodes;

namespace OpenIddict.Client.Saml.AspNetCore;

/// <summary>
/// Provides the entry point necessary to use the OpenIddict SAML 2.0 service provider in an ASP.NET Core pipeline:
/// challenges send authentication requests to the identity provider, the assertion consumer service validates the
/// responses and signs the user in and the metadata endpoint returns the service provider metadata.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Never)]
public sealed class OpenIddictClientSamlAspNetCoreHandler : AuthenticationHandler<AuthenticationSchemeOptions>, IAuthenticationRequestHandler
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientSamlAspNetCoreHandler"/> class.
    /// </summary>
    public OpenIddictClientSamlAspNetCoreHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    /// <inheritdoc/>
    public async Task<bool> HandleRequestAsync()
    {
        var options = GetOptions();

        if (Request.Path == options.MetadataPath)
        {
            if (!HttpMethods.IsGet(Request.Method))
            {
                Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                return true;
            }

            if (!ValidateTransportSecurity(options))
            {
                await WriteErrorAsync(SR.GetResourceString(SR.ID2458));
                return true;
            }

            Response.ContentType = MediaTypes.Metadata;
            await Response.WriteAsync(GetService().CreateMetadata(GetUrl(options.AssertionConsumerServicePath)), Encoding.UTF8, Context.RequestAborted);
            return true;
        }

        if (Request.Path != options.AssertionConsumerServicePath)
        {
            return false;
        }

        if (!ValidateTransportSecurity(options))
        {
            await WriteErrorAsync(SR.GetResourceString(SR.ID2458));
            return true;
        }

        // SAML bindings, 3.5.4: the response is sent as a form-encoded "SAMLResponse" parameter (HTTP-POST binding).
        if (!HttpMethods.IsPost(Request.Method) || !Request.HasFormContentType)
        {
            await WriteErrorAsync(SR.GetResourceString(SR.ID2440));
            return true;
        }

        var form = await Request.ReadFormAsync(Context.RequestAborted);
        if (form[Parameters.SamlResponse].Count is not 1 || form[Parameters.RelayState].Count > 1)
        {
            await WriteErrorAsync(SR.GetResourceString(SR.ID2440));
            return true;
        }

        var relayState = form.ContainsKey(Parameters.RelayState) ? form[Parameters.RelayState].ToString() : null;

        // Restore the request state from the correlation cookie associated with the relay state, if applicable.
        RequestState? state = null;

        if (IsCorrelationIdentifier(relayState))
        {
            var name = options.CorrelationCookie.Name + relayState;
            if (Request.Cookies.TryGetValue(name, out var value))
            {
                state = Context.RequestServices.GetRequiredService<OpenIddictClientSamlAspNetCoreStateProtector>().Unprotect(value);

                // Note: the correlation cookie is always removed to ensure it cannot be used again.
                Response.Cookies.Delete(name, BuildCookieOptions(options));
            }
        }

        var result = await GetService().ValidateResponseAsync(form[Parameters.SamlResponse].ToString(),
            relayState, state, GetUrl(options.AssertionConsumerServicePath), Context.RequestAborted);

        Context.Features.Set(new OpenIddictClientSamlAspNetCoreFeature { Result = result });

        if (options.EnableAssertionConsumerServicePassthrough)
        {
            return false;
        }

        if (!result.Succeeded)
        {
            await WriteErrorAsync(result.ErrorDescription!);
            return true;
        }

        var scheme = options.SignInScheme ?? (await Context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>()
            .GetDefaultSignInSchemeAsync())?.Name ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0910));

        var properties = CreateProperties(result);

        await Context.SignInAsync(scheme, result.Principal!, properties);

        Response.Headers.CacheControl = "no-cache, no-store";
        Response.Redirect(properties.RedirectUri ?? "/");

        return true;
    }

    /// <inheritdoc/>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Context.Features.Get<OpenIddictClientSamlAspNetCoreFeature>()?.Result is not ResponseValidationResult result)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        if (!result.Succeeded)
        {
            return Task.FromResult(AuthenticateResult.Fail(result.ErrorDescription!));
        }

        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(result.Principal!, CreateProperties(result), Scheme.Name)));
    }

    /// <inheritdoc/>
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var options = GetOptions();
        var service = GetService();

        OpenIddictClientSamlRegistration registration;

        if (properties.Items.TryGetValue(Properties.RegistrationId, out var identifier) && !string.IsNullOrEmpty(identifier))
        {
            registration = await service.GetRegistrationByIdAsync(identifier, Context.RequestAborted);
        }

        else if (properties.Items.TryGetValue(Properties.ProviderName, out var name) && !string.IsNullOrEmpty(name))
        {
            registration = await service.GetRegistrationByProviderNameAsync(name, Context.RequestAborted);
        }

        else
        {
            registration = await service.GetRegistrationsAsync(Context.RequestAborted) switch
            {
                [var candidate] => candidate,
                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0901))
            };
        }

        // Note: as with the other remote authentication handlers, the current URL is used as the default return URL.
        properties.RedirectUri ??= OriginalPathBase + OriginalPath + Request.QueryString;
        properties.Items[Properties.RegistrationId] = registration.RegistrationId;
        properties.Items[Properties.ProviderName] = registration.ProviderName;

        // Note: the relay state is a random correlation identifier (SAML bindings, 3.4.3 and 3.5.3 restrict it
        // to 80 bytes) used to locate the cookie storing the protected request state (and the return URL).
        var relayState = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(24));
        var acs = GetUrl(options.AssertionConsumerServicePath);

        var request = await service.CreateAuthenticationRequestAsync(registration, acs, relayState, Context.RequestAborted);
        var state = service.CreateRequestState(registration, request, acs, properties.Items);

        var cookie = BuildCookieOptions(options);
        cookie.Expires = state.ExpirationDate;

        Response.Cookies.Append(options.CorrelationCookie.Name + relayState,
            Context.RequestServices.GetRequiredService<OpenIddictClientSamlAspNetCoreStateProtector>().Protect(state), cookie);

        Response.Headers.CacheControl = "no-cache, no-store";
        Response.Headers.Pragma = "no-cache";

        if (request.RedirectUrl is Uri url)
        {
            Response.Redirect(url.AbsoluteUri);
            return;
        }

        var nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

        Response.StatusCode = StatusCodes.Status200OK;
        Response.Headers.ContentSecurityPolicy = OpenIddictClientSamlService.CreateFormPostContentSecurityPolicy(request, nonce);
        Response.ContentType = "text/html; charset=utf-8";

        await Response.WriteAsync(OpenIddictClientSamlService.CreateFormPostPage(request, nonce), Encoding.UTF8, Context.RequestAborted);
    }

    private CookieOptions BuildCookieOptions(OpenIddictClientSamlAspNetCoreOptions options)
    {
        var cookie = options.CorrelationCookie.Build(Context, TimeProvider.GetUtcNow());

        // Note: unless explicitly configured, the cookie is restricted to the assertion consumer service.
        if (string.IsNullOrEmpty(options.CorrelationCookie.Path))
        {
            cookie.Path = (OriginalPathBase + options.AssertionConsumerServicePath).Value;
        }

        return cookie;
    }

    private static AuthenticationProperties CreateProperties(ResponseValidationResult result)
    {
        if (result.State is RequestState state)
        {
            return new AuthenticationProperties(state.Properties.ToDictionary(StringComparer.Ordinal));
        }

        // Note: for unsolicited responses, the relay state is only used as the return URL if it's a local URL.
        var properties = new AuthenticationProperties
        {
            RedirectUri = IsLocalUrl(result.RelayState) ? result.RelayState : "/"
        };

        properties.Items[Properties.RegistrationId] = result.Registration?.RegistrationId;
        properties.Items[Properties.ProviderName] = result.Registration?.ProviderName;

        return properties;
    }

    private static bool IsCorrelationIdentifier(string? value)
        => value is { Length: > 0 and <= 64 } && value.All(static character => character is
            (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');

    private static bool IsLocalUrl(string? value)
        => value is { Length: > 0 } && value[0] is '/' &&
           (value.Length is 1 || (value[1] is not ('/' or '\\') && !value.Any(char.IsControl)));

    private OpenIddictClientSamlAspNetCoreOptions GetOptions()
        => Context.RequestServices.GetService<IOptionsMonitor<OpenIddictClientSamlAspNetCoreOptions>>()?.CurrentValue ??
           throw new InvalidOperationException(SR.GetResourceString(SR.ID0900));

    private OpenIddictClientSamlService GetService()
        => Context.RequestServices.GetService<OpenIddictClientSamlService>() ??
           throw new InvalidOperationException(SR.GetResourceString(SR.ID0900));

    private bool ValidateTransportSecurity(OpenIddictClientSamlAspNetCoreOptions options)
        => options.DisableTransportSecurityRequirement || Request.IsHttps;

    private Uri GetUrl(PathString path)
        => new(UriHelper.BuildAbsolute(Request.Scheme, Request.Host, OriginalPathBase, path), UriKind.Absolute);

    private Task WriteErrorAsync(string description)
    {
        Response.StatusCode = StatusCodes.Status400BadRequest;
        Response.Headers.CacheControl = "no-cache, no-store";
        Response.ContentType = "text/plain; charset=utf-8";
        Response.Headers.XContentTypeOptions = "nosniff";

        return Response.WriteAsync(description, Encoding.UTF8, Context.RequestAborted);
    }
}
