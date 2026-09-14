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
            GetEndpointUrl(context, options.ArtifactResolutionPath));

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

        var assertion = await context.RequestServices.GetRequiredService<IOpenIddictServerSamlAssertionProvider>()
            .CreateAssertionAsync(new AssertionContext
            {
                AuthenticationInstant = authentication.Properties?.IssuedUtc,
                CancellationToken = context.RequestAborted,
                Principal = authentication.Principal!,
                Request = result.Request,
                ServiceProvider = result.ServiceProvider!
            });

        if (assertion is null)
        {
            await WriteErrorResponseAsync(result, SamlStatusCodes.Responder, SamlStatusCodes.RequestDenied, SR.GetResourceString(SR.ID2261));
            return;
        }

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

    private static Uri GetEndpointUrl(HttpContext context, PathString path)
        => new(UriHelper.BuildAbsolute(context.Request.Scheme, context.Request.Host, context.Request.PathBase, path), UriKind.Absolute);
}
