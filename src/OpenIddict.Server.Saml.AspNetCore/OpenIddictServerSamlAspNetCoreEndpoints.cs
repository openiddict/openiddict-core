/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using SamlStatusCodes = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.StatusCodes;
using StatusCodes = Microsoft.AspNetCore.Http.StatusCodes;

namespace OpenIddict.Server.Saml.AspNetCore;

/// <summary>
/// Contains the request delegates of the SAML 2.0 identity provider endpoints.
/// </summary>
internal static class OpenIddictServerSamlAspNetCoreEndpoints
{
    /// <summary>
    /// Handles metadata requests.
    /// </summary>
    public static async Task MetadataAsync(HttpContext context)
    {
        var options = GetOptions(context);
        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var service = GetService(context);

        var metadata = service.CreateMetadata(GetEndpointUrl(context, options.SingleSignOnPath),
            GetEndpointUrl(context, options.ArtifactResolutionPath), GetEndpointUrl(context, options.SingleLogoutPath));

        context.Response.ContentType = MediaTypes.Metadata;
        await context.Response.WriteAsync(metadata, Encoding.UTF8, context.RequestAborted);
    }

    /// <summary>
    /// Handles single sign-on requests.
    /// </summary>
    public static async Task SingleSignOnAsync(HttpContext context)
    {
        var options = GetOptions(context);
        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var service = GetService(context);
        var protector = context.RequestServices.GetRequiredService<OpenIddictServerSamlAspNetCoreStateProtector>();

        var endpoint = GetEndpointUrl(context, options.SingleSignOnPath);
        var request = context.Request;

        AuthenticationRequestResult result;
        RequestState? state = null;

        if (HttpMethods.IsGet(request.Method) && request.Query.ContainsKey(Parameters.State))
        {
            state = request.Query[Parameters.State].Count is 1 ? protector.Unprotect(request.Query[Parameters.State]) : null;

            // Note: the service provider is resolved again to ensure it was not removed or updated.
            result = await service.ValidateRequestStateAsync(state, context.RequestAborted);
            if (state is null || !result.Succeeded)
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2263));
                return;
            }
        }

        else if (HttpMethods.IsGet(request.Method) && request.Query.ContainsKey(Parameters.SamlRequest))
        {
            result = await service.ValidateRedirectAuthenticationRequestAsync(request.QueryString.Value, endpoint, context.RequestAborted);
        }

        else if (HttpMethods.IsPost(request.Method) && request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(context.RequestAborted);
            if (form[Parameters.SamlRequest].Count > 1 || form[Parameters.RelayState].Count > 1)
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2259));
                return;
            }

            result = await service.ValidatePostAuthenticationRequestAsync(
                form[Parameters.SamlRequest], form.ContainsKey(Parameters.RelayState) ? form[Parameters.RelayState].ToString() : null,
                endpoint, context.RequestAborted);
        }

        else if (HttpMethods.IsGet(request.Method) && request.Query.ContainsKey(Parameters.ServiceProvider))
        {
            if (request.Query[Parameters.ServiceProvider].Count > 1 || request.Query[Parameters.RelayState].Count > 1)
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2259));
                return;
            }

            result = await service.ValidateIdentityProviderInitiatedRequestAsync(request.Query[Parameters.ServiceProvider],
                request.Query.ContainsKey(Parameters.RelayState) ? request.Query[Parameters.RelayState].ToString() : null,
                context.RequestAborted);
        }

        else
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2266));
            return;
        }

        if (!result.Succeeded)
        {
            if (result.CanReturnErrorToServiceProvider)
            {
                await WriteErrorResponseAsync(result, result.Status!, result.SecondLevelStatus, result.ErrorDescription);
            }

            else
            {
                await WriteErrorAsync(context, result.ErrorDescription!);
            }

            return;
        }

        var authentication = await context.AuthenticateAsync(options.AuthenticationScheme);

        var authenticated = authentication.Succeeded && authentication.Principal.Identity?.IsAuthenticated is true;
        if (authenticated && result.Request?.ForceAuthentication is true)
        {
            // When authentication is forced, the user must have been authenticated after the request was received.
            // For requests that were just received, a challenge is always triggered.
            authenticated = state is not null && authentication.Properties?.IssuedUtc >= state.CreationDate;
        }

        if (!authenticated)
        {
            if (result.Request?.IsPassive is true)
            {
                await WriteErrorResponseAsync(result, SamlStatusCodes.Responder, SamlStatusCodes.NoPassive, SR.GetResourceString(SR.ID2260));
                return;
            }

            state ??= service.CreateRequestState(result, options.RequestStateLifetime);

            var properties = new AuthenticationProperties
            {
                RedirectUri = QueryHelpers.AddQueryString(
                    request.PathBase.Add(options.SingleSignOnPath).Value!, Parameters.State, protector.Protect(state))
            };

            await context.ChallengeAsync(options.AuthenticationScheme, properties);
            return;
        }

        var assertionContext = new AssertionContext
        {
            AuthenticationInstant = authentication.Properties?.IssuedUtc,
            CancellationToken = context.RequestAborted,
            Principal = authentication.Principal!,
            Request = result.Request,
            ServiceProvider = result.ServiceProvider!
        };

        var assertion = await context.RequestServices.GetRequiredService<IOpenIddictServerSamlAssertionProvider>()
            .CreateAssertionAsync(assertionContext);

        if (assertion is null)
        {
            await WriteErrorResponseAsync(result, SamlStatusCodes.Responder, SamlStatusCodes.RequestDenied, SR.GetResourceString(SR.ID2261));
            return;
        }

        // When single logout is enabled, the session of the user at the service provider is tracked server-side.
        assertion = await context.RequestServices.GetRequiredService<OpenIddictServerSamlLogoutService>()
            .AttachSessionAsync(assertionContext, assertion);

        await WriteResponseAsync(context, service, result, service.CreateResponse(new ResponseDescriptor
        {
            Assertion = assertion,
            AssertionConsumerServiceUrl = result.AssertionConsumerServiceUrl!,
            InResponseTo = result.RequestId,
            ServiceProvider = result.ServiceProvider!
        }), ConsumeRequestStateAsync);

        // Note: when request replay protection is enabled, a request state can only be used once to return a response.
        // The state is only consumed once the response was successfully created (and stored, for the HTTP-Artifact
        // binding) so that transient failures (e.g a distributed cache outage) don't prevent the user from retrying.
        async Task<bool> ConsumeRequestStateAsync()
        {
            if (state is null || await service.ConsumeRequestStateAsync(state, context.RequestAborted))
            {
                return true;
            }

            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2263));
            return false;
        }

        Task WriteErrorResponseAsync(AuthenticationRequestResult result, string status, string? secondLevelStatus, string? description)
            => WriteResponseAsync(context, service, result, service.CreateResponse(new ResponseDescriptor
            {
                AssertionConsumerServiceUrl = result.AssertionConsumerServiceUrl!,
                InResponseTo = result.RequestId,
                SecondLevelStatus = secondLevelStatus,
                ServiceProvider = result.ServiceProvider!,
                Status = status,
                StatusMessage = description
            }), ConsumeRequestStateAsync);
    }

    /// <summary>
    /// Handles artifact resolution requests (SOAP binding).
    /// </summary>
    public static async Task ArtifactResolutionAsync(HttpContext context)
    {
        var options = GetOptions(context);

        if (context.RequestServices.GetService<IOptionsMonitor<OpenIddictServerSamlOptions>>()?.CurrentValue is not { EnableArtifactBinding: true })
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var result = await GetService(context).ResolveArtifactAsync(context.Request.Body,
            GetEndpointUrl(context, options.ArtifactResolutionPath), context.RequestAborted);

        // Note: SOAP faults are returned with a 500 status code and SOAP responses must not be cached (SAML bindings, 3.2.3.3).
        context.Response.StatusCode = result.IsFault ? StatusCodes.Status500InternalServerError : StatusCodes.Status200OK;
        context.Response.Headers.CacheControl = "no-cache, no-store";
        context.Response.Headers.Pragma = "no-cache";
        context.Response.ContentType = MediaTypes.Soap + "; charset=utf-8";

        await context.Response.WriteAsync(result.Content, Encoding.UTF8, context.RequestAborted);
    }

    /// <summary>
    /// Handles single logout requests and responses (HTTP-Redirect, HTTP-POST and SOAP bindings).
    /// </summary>
    public static async Task SingleLogoutAsync(HttpContext context)
    {
        var options = GetOptions(context);

        if (context.RequestServices.GetService<IOptionsMonitor<OpenIddictServerSamlOptions>>()?.CurrentValue is not { EnableSingleLogout: true })
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var service = context.RequestServices.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var endpoint = GetEndpointUrl(context, options.SingleLogoutPath);
        var request = context.Request;

        LogoutRequestResult? requestResult = null;
        LogoutResponseResult? responseResult = null;

        // Logout requests sent using the SOAP binding are posted as text/xml SOAP 1.1 envelopes (SAML bindings, 3.2.3.1).
        if (HttpMethods.IsPost(request.Method) && request.ContentType is { Length: > 0 } type &&
            type.StartsWith(MediaTypes.Soap, StringComparison.OrdinalIgnoreCase))
        {
            var soap = await service.ProcessSoapLogoutRequestAsync(request.Body, endpoint, GetBaseUri(context), context.RequestAborted);

            // Note: SOAP faults are returned with a 500 status code and SOAP responses must not be cached (SAML bindings, 3.2.3.3).
            context.Response.StatusCode = soap.IsFault ? StatusCodes.Status500InternalServerError : StatusCodes.Status200OK;
            context.Response.Headers.CacheControl = "no-cache, no-store";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.ContentType = MediaTypes.Soap + "; charset=utf-8";

            await context.Response.WriteAsync(soap.Content, Encoding.UTF8, context.RequestAborted);
            return;
        }

        if (HttpMethods.IsGet(request.Method) && request.Query.ContainsKey(Parameters.SamlRequest))
        {
            requestResult = await service.ValidateRedirectLogoutRequestAsync(request.QueryString.Value, endpoint, context.RequestAborted);
        }

        else if (HttpMethods.IsGet(request.Method) && request.Query.ContainsKey(Parameters.SamlResponse))
        {
            responseResult = await service.ValidateRedirectLogoutResponseAsync(request.QueryString.Value, endpoint, context.RequestAborted);
        }

        else if (HttpMethods.IsPost(request.Method) && request.HasFormContentType)
        {
            var form = await request.ReadFormAsync(context.RequestAborted);
            if (form[Parameters.SamlRequest].Count > 1 || form[Parameters.SamlResponse].Count > 1 || form[Parameters.RelayState].Count > 1 ||
               (form.ContainsKey(Parameters.SamlRequest) && form.ContainsKey(Parameters.SamlResponse)))
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2259));
                return;
            }

            var relayState = form.ContainsKey(Parameters.RelayState) ? form[Parameters.RelayState].ToString() : null;

            if (form.ContainsKey(Parameters.SamlRequest))
            {
                requestResult = await service.ValidatePostLogoutRequestAsync(form[Parameters.SamlRequest], relayState, endpoint, context.RequestAborted);
            }

            else if (form.ContainsKey(Parameters.SamlResponse))
            {
                responseResult = await service.ValidatePostLogoutResponseAsync(form[Parameters.SamlResponse], relayState, endpoint, context.RequestAborted);
            }
        }

        LogoutAction action;

        if (requestResult is not null)
        {
            if (!requestResult.Succeeded)
            {
                if (!requestResult.CanReturnErrorToServiceProvider)
                {
                    await WriteErrorAsync(context, requestResult.ErrorDescription!);
                    return;
                }

                action = service.CreateErrorResponseAction(requestResult);
            }

            else
            {
                var authentication = await context.AuthenticateAsync(options.AuthenticationScheme);

                action = await service.ProcessLogoutRequestAsync(requestResult,
                    authentication.Succeeded ? authentication.Principal : null, GetBaseUri(context), context.RequestAborted);

                if (action.SignOut)
                {
                    await context.SignOutAsync(options.AuthenticationScheme);
                }
            }
        }

        else if (responseResult is not null)
        {
            if (!responseResult.Succeeded)
            {
                // Note: when the rejected response corresponds to a pending logout, the logout is propagated to the remaining
                // participants instead of being aborted (SAML profiles, 4.4.3.4), which ultimately results in a partial logout.
                if (await service.ProcessRejectedLogoutResponseAsync(responseResult, context.RequestAborted) is not LogoutAction resumed)
                {
                    await WriteErrorAsync(context, responseResult.ErrorDescription!);
                    return;
                }

                action = resumed;
            }

            else
            {
                action = await service.ProcessLogoutResponseAsync(responseResult, context.RequestAborted);
            }
        }

        else
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2511));
            return;
        }

        await WriteLogoutActionAsync(context, action);
    }

    /// <summary>
    /// Writes the response corresponding to the specified logout action.
    /// </summary>
    internal static Task WriteLogoutActionAsync(HttpContext context, LogoutAction action)
    {
        var headers = context.Response.Headers;
        headers.CacheControl = "no-cache, no-store";
        headers.Pragma = "no-cache";

        if (action.FormPostUrl is null && action.FrontchannelLogoutUris.Count is 0)
        {
            if (action.RedirectUrl is not null)
            {
                context.Response.StatusCode = StatusCodes.Status303SeeOther;
                headers.Location = action.RedirectUrl.OriginalString;
                return Task.CompletedTask;
            }

            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "text/plain; charset=utf-8";
            return context.Response.WriteAsync(SR.GetResourceString(SR.ID8200), Encoding.UTF8, context.RequestAborted);
        }

        var nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

        headers.ContentSecurityPolicy = OpenIddictServerSamlLogoutService.CreateLogoutContentSecurityPolicy(action, nonce);
        context.Response.ContentType = "text/html; charset=utf-8";

        return context.Response.WriteAsync(OpenIddictServerSamlLogoutService.CreateLogoutPage(action, nonce), Encoding.UTF8, context.RequestAborted);
    }

    private static async Task WriteResponseAsync(HttpContext context, OpenIddictServerSamlService service,
        AuthenticationRequestResult result, string response, Func<Task<bool>> consumeRequestStateAsync)
    {
        var url = result.AssertionConsumerServiceUrl!;

        // When the HTTP-Artifact binding is used, the response is stored and the user agent is redirected to
        // the assertion consumer service with the artifact representing it (SAML bindings, 3.6.3.2 and 3.6.5).
        if (result.ResponseBinding is Bindings.HttpArtifact)
        {
            var artifact = await service.CreateArtifactAsync(result.ServiceProvider!, response, context.RequestAborted);

            if (!await consumeRequestStateAsync())
            {
                return;
            }

            context.Response.StatusCode = StatusCodes.Status303SeeOther;
            context.Response.Headers.CacheControl = "no-cache, no-store";
            context.Response.Headers.Pragma = "no-cache";
            context.Response.Headers.Location = OpenIddictServerSamlService.CreateArtifactRedirectUrl(
                url, artifact, result.RelayState).AbsoluteUri;
            return;
        }

        if (!await consumeRequestStateAsync())
        {
            return;
        }

        var nonce = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));

        var headers = context.Response.Headers;
        headers.CacheControl = "no-cache, no-store";
        headers.Pragma = "no-cache";
        headers.ContentSecurityPolicy = $"default-src 'none'; script-src 'nonce-{nonce}'; " +
            $"form-action {url.GetLeftPart(UriPartial.Authority)}; frame-ancestors 'none'; base-uri 'none'";

        context.Response.ContentType = "text/html; charset=utf-8";

        await context.Response.WriteAsync(OpenIddictServerSamlService.CreateFormPostPage(
            url, response, result.RelayState, nonce), Encoding.UTF8, context.RequestAborted);
    }

    private static Task WriteErrorAsync(HttpContext context, string description)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.Headers.CacheControl = "no-cache, no-store";
        context.Response.ContentType = "text/plain; charset=utf-8";

        return context.Response.WriteAsync(description, Encoding.UTF8, context.RequestAborted);
    }

    private static OpenIddictServerSamlAspNetCoreOptions GetOptions(HttpContext context)
        => context.RequestServices.GetService<IOptionsMonitor<OpenIddictServerSamlAspNetCoreOptions>>()?.CurrentValue ??
           throw new InvalidOperationException(SR.GetResourceString(SR.ID0571));

    private static OpenIddictServerSamlService GetService(HttpContext context)
        => context.RequestServices.GetService<OpenIddictServerSamlService>() ??
           throw new InvalidOperationException(SR.GetResourceString(SR.ID0571));

    private static bool ValidateTransportSecurity(HttpContext context, OpenIddictServerSamlAspNetCoreOptions options)
        => options.DisableTransportSecurityRequirement || context.Request.IsHttps;

    /// <summary>
    /// Gets the absolute base URI of the current request (built the same way as by the OpenIddict server ASP.NET Core host).
    /// </summary>
    internal static Uri? GetBaseUri(HttpContext context)
        => Uri.TryCreate(UriHelper.BuildAbsolute(context.Request.Scheme, context.Request.Host, context.Request.PathBase),
            UriKind.Absolute, out var uri) ? uri : null;

    private static Uri GetEndpointUrl(HttpContext context, PathString path)
        => new(UriHelper.BuildAbsolute(context.Request.Scheme, context.Request.Host, context.Request.PathBase, path), UriKind.Absolute);
}
