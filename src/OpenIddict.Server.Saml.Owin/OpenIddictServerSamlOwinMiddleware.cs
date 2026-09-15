/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using SamlStatusCodes = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.StatusCodes;

namespace OpenIddict.Server.Saml.Owin;

/// <summary>
/// Handles the SAML 2.0 identity provider metadata and single sign-on endpoints in an OWIN/Katana pipeline.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerSamlOwinMiddleware : OwinMiddleware
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlOwinMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline, if applicable.</param>
    public OpenIddictServerSamlOwinMiddleware(OwinMiddleware? next)
        : base(next)
    {
    }

    /// <inheritdoc/>
    public override Task Invoke(IOwinContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var provider = context.Get<IServiceProvider>(typeof(IServiceProvider).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0578));

        var options = provider.GetService<IOptionsMonitor<OpenIddictServerSamlOwinOptions>>()?.CurrentValue ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0578));

        if (context.Request.Path == options.MetadataPath)
        {
            return MetadataAsync(context, provider, options);
        }

        if (context.Request.Path == options.SingleSignOnPath)
        {
            return SingleSignOnAsync(context, provider, options);
        }

        // Note: the artifact resolution endpoint is only handled when the HTTP-Artifact binding is enabled.
        if (context.Request.Path == options.ArtifactResolutionPath &&
            provider.GetService<IOptionsMonitor<OpenIddictServerSamlOptions>>()?.CurrentValue is { EnableArtifactBinding: true })
        {
            return ArtifactResolutionAsync(context, provider, options);
        }

        // Note: the single logout endpoint is only handled when single logout is enabled.
        if (context.Request.Path == options.SingleLogoutPath &&
            provider.GetService<IOptionsMonitor<OpenIddictServerSamlOptions>>()?.CurrentValue is { EnableSingleLogout: true })
        {
            return SingleLogoutAsync(context, provider, options);
        }

        return Next?.Invoke(context) ?? Task.CompletedTask;
    }

    private static async Task MetadataAsync(IOwinContext context, IServiceProvider provider, OpenIddictServerSamlOwinOptions options)
    {
        if (!IsGet(context.Request))
        {
            context.Response.StatusCode = 405;
            return;
        }

        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var service = GetService(provider);
        var metadata = service.CreateMetadata(GetEndpointUrl(context, options.SingleSignOnPath),
            GetEndpointUrl(context, options.ArtifactResolutionPath), GetEndpointUrl(context, options.SingleLogoutPath));

        context.Response.ContentType = MediaTypes.Metadata;
        await WriteAsync(context, metadata);
    }

    private static async Task ArtifactResolutionAsync(IOwinContext context, IServiceProvider provider, OpenIddictServerSamlOwinOptions options)
    {
        if (!IsPost(context.Request))
        {
            context.Response.StatusCode = 405;
            return;
        }

        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var result = await GetService(provider).ResolveArtifactAsync(context.Request.Body,
            GetEndpointUrl(context, options.ArtifactResolutionPath), context.Request.CallCancelled);

        // Note: SOAP faults are returned with a 500 status code and SOAP responses must not be cached (SAML bindings, 3.2.3.3).
        context.Response.StatusCode = result.IsFault ? 500 : 200;
        context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
        context.Response.Headers.Set("Pragma", "no-cache");
        context.Response.ContentType = MediaTypes.Soap + "; charset=utf-8";

        await WriteAsync(context, result.Content);
    }

    private static async Task SingleSignOnAsync(IOwinContext context, IServiceProvider provider, OpenIddictServerSamlOwinOptions options)
    {
        if (!IsGet(context.Request) && !IsPost(context.Request))
        {
            context.Response.StatusCode = 405;
            return;
        }

        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var service = GetService(provider);
        var protector = provider.GetRequiredService<OpenIddictServerSamlOwinStateProtector>();

        var endpoint = GetEndpointUrl(context, options.SingleSignOnPath);
        var request = context.Request;
        var cancellationToken = request.CallCancelled;

        AuthenticationRequestResult result;
        RequestState? state = null;

        if (IsGet(request) && request.Query.GetValues(Parameters.State) is { } values)
        {
            state = values.Count is 1 ? protector.Unprotect(values[0]) : null;

            // Note: the service provider is resolved again to ensure it was not removed or updated.
            result = await service.ValidateRequestStateAsync(state, cancellationToken);
            if (state is null || !result.Succeeded)
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2263));
                return;
            }
        }

        else if (IsGet(request) && request.Query.GetValues(Parameters.SamlRequest) is not null)
        {
            result = await service.ValidateRedirectAuthenticationRequestAsync(request.QueryString.Value, endpoint, cancellationToken);
        }

        else if (IsPost(request) && request.ContentType is { Length: > 0 } type &&
            type.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var form = await request.ReadFormAsync();
            if (form.GetValues(Parameters.SamlRequest) is { Count: > 1 } || form.GetValues(Parameters.RelayState) is { Count: > 1 })
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2259));
                return;
            }

            result = await service.ValidatePostAuthenticationRequestAsync(
                form.Get(Parameters.SamlRequest), form.Get(Parameters.RelayState), endpoint, cancellationToken);
        }

        else if (IsGet(request) && request.Query.GetValues(Parameters.ServiceProvider) is { } providers)
        {
            if (providers.Count > 1 || request.Query.GetValues(Parameters.RelayState) is { Count: > 1 })
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2259));
                return;
            }

            result = await service.ValidateIdentityProviderInitiatedRequestAsync(
                providers[0], request.Query.Get(Parameters.RelayState), cancellationToken);
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

        var authentication = await context.Authentication.AuthenticateAsync(options.AuthenticationType);

        var authenticated = authentication?.Identity is { IsAuthenticated: true };
        if (authenticated && result.Request?.ForceAuthentication is true)
        {
            // When authentication is forced, the user must have been authenticated after the request was received.
            // For requests that were just received, a challenge is always triggered.
            authenticated = state is not null && authentication!.Properties?.IssuedUtc >= state.CreationDate;
        }

        if (!authenticated)
        {
            if (result.Request?.IsPassive is true)
            {
                await WriteErrorResponseAsync(result, SamlStatusCodes.Responder, SamlStatusCodes.NoPassive, SR.GetResourceString(SR.ID2260));
                return;
            }

            // Note: unlike ASP.NET Core, the meaning of AuthenticationProperties.RedirectUri depends on the Katana
            // middleware (e.g the cookies middleware uses it as the login page address). To support all the
            // authentication middleware, the user agent is first redirected to the address containing the
            // protected state, that is used as the return address when the challenge is triggered.
            if (state is null)
            {
                state = service.CreateRequestState(result, options.RequestStateLifetime);

                context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
                context.Response.Redirect(request.PathBase.Add(options.SingleSignOnPath).ToUriComponent() + "?" +
                    Parameters.State + "=" + Uri.EscapeDataString(protector.Protect(state)));
                return;
            }

            context.Response.StatusCode = 401;
            context.Authentication.Challenge(new AuthenticationProperties(), options.AuthenticationType);
            return;
        }

        var assertionContext = new AssertionContext
        {
            AuthenticationInstant = authentication!.Properties?.IssuedUtc,
            CancellationToken = cancellationToken,
            Principal = new ClaimsPrincipal(authentication.Identity),
            Request = result.Request,
            ServiceProvider = result.ServiceProvider!
        };

        var assertion = await provider.GetRequiredService<IOpenIddictServerSamlAssertionProvider>()
            .CreateAssertionAsync(assertionContext);

        if (assertion is null)
        {
            await WriteErrorResponseAsync(result, SamlStatusCodes.Responder, SamlStatusCodes.RequestDenied, SR.GetResourceString(SR.ID2261));
            return;
        }

        // When single logout is enabled, the session of the user at the service provider is tracked server-side.
        assertion = await provider.GetRequiredService<OpenIddictServerSamlLogoutService>().AttachSessionAsync(assertionContext, assertion);

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
            if (state is null || await service.ConsumeRequestStateAsync(state, cancellationToken))
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

    private static async Task SingleLogoutAsync(IOwinContext context, IServiceProvider provider, OpenIddictServerSamlOwinOptions options)
    {
        if (!IsGet(context.Request) && !IsPost(context.Request))
        {
            context.Response.StatusCode = 405;
            return;
        }

        if (!ValidateTransportSecurity(context, options))
        {
            await WriteErrorAsync(context, SR.GetResourceString(SR.ID2264));
            return;
        }

        var service = provider.GetRequiredService<OpenIddictServerSamlLogoutService>();
        var endpoint = GetEndpointUrl(context, options.SingleLogoutPath);
        var request = context.Request;
        var cancellationToken = request.CallCancelled;

        LogoutRequestResult? requestResult = null;
        LogoutResponseResult? responseResult = null;

        // Logout requests sent using the SOAP binding are posted as text/xml SOAP 1.1 envelopes (SAML bindings, 3.2.3.1).
        if (IsPost(request) && request.ContentType is { Length: > 0 } contentType &&
            contentType.StartsWith(MediaTypes.Soap, StringComparison.OrdinalIgnoreCase))
        {
            var soap = await service.ProcessSoapLogoutRequestAsync(request.Body, endpoint, GetBaseUri(context), cancellationToken);

            // Note: SOAP faults are returned with a 500 status code and SOAP responses must not be cached (SAML bindings, 3.2.3.3).
            context.Response.StatusCode = soap.IsFault ? 500 : 200;
            context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
            context.Response.Headers.Set("Pragma", "no-cache");
            context.Response.ContentType = MediaTypes.Soap + "; charset=utf-8";

            await WriteAsync(context, soap.Content);
            return;
        }

        if (IsGet(request) && request.Query.GetValues(Parameters.SamlRequest) is not null)
        {
            requestResult = await service.ValidateRedirectLogoutRequestAsync(request.QueryString.Value, endpoint, cancellationToken);
        }

        else if (IsGet(request) && request.Query.GetValues(Parameters.SamlResponse) is not null)
        {
            responseResult = await service.ValidateRedirectLogoutResponseAsync(request.QueryString.Value, endpoint, cancellationToken);
        }

        else if (IsPost(request) && request.ContentType is { Length: > 0 } type &&
            type.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            var form = await request.ReadFormAsync();
            if (form.GetValues(Parameters.SamlRequest) is { Count: > 1 } || form.GetValues(Parameters.SamlResponse) is { Count: > 1 } ||
                form.GetValues(Parameters.RelayState) is { Count: > 1 } ||
               (form.GetValues(Parameters.SamlRequest) is not null && form.GetValues(Parameters.SamlResponse) is not null))
            {
                await WriteErrorAsync(context, SR.GetResourceString(SR.ID2259));
                return;
            }

            if (form.GetValues(Parameters.SamlRequest) is not null)
            {
                requestResult = await service.ValidatePostLogoutRequestAsync(
                    form.Get(Parameters.SamlRequest), form.Get(Parameters.RelayState), endpoint, cancellationToken);
            }

            else if (form.GetValues(Parameters.SamlResponse) is not null)
            {
                responseResult = await service.ValidatePostLogoutResponseAsync(
                    form.Get(Parameters.SamlResponse), form.Get(Parameters.RelayState), endpoint, cancellationToken);
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
                var authentication = await context.Authentication.AuthenticateAsync(options.AuthenticationType);

                action = await service.ProcessLogoutRequestAsync(requestResult,
                    authentication?.Identity is { IsAuthenticated: true } identity ? new ClaimsPrincipal(identity) : null,
                    GetBaseUri(context), cancellationToken);

                if (action.SignOut)
                {
                    context.Authentication.SignOut(options.AuthenticationType);
                }
            }
        }

        else if (responseResult is not null)
        {
            if (!responseResult.Succeeded)
            {
                // Note: when the rejected response corresponds to a pending logout, the logout is propagated to the remaining
                // participants instead of being aborted (SAML profiles, 4.4.3.4), which ultimately results in a partial logout.
                if (await service.ProcessRejectedLogoutResponseAsync(responseResult, cancellationToken) is not LogoutAction resumed)
                {
                    await WriteErrorAsync(context, responseResult.ErrorDescription!);
                    return;
                }

                action = resumed;
            }

            else
            {
                action = await service.ProcessLogoutResponseAsync(responseResult, cancellationToken);
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
    internal static Task WriteLogoutActionAsync(IOwinContext context, LogoutAction action)
    {
        var headers = context.Response.Headers;
        headers.Set("Cache-Control", "no-cache, no-store");
        headers.Set("Pragma", "no-cache");

        if (action.FormPostUrl is null && action.FrontchannelLogoutUris.Count is 0)
        {
            if (action.RedirectUrl is not null)
            {
                context.Response.StatusCode = 303;
                headers.Set("Location", action.RedirectUrl.OriginalString);
                return Task.CompletedTask;
            }

            context.Response.StatusCode = 200;
            context.Response.ContentType = "text/plain; charset=utf-8";
            return WriteAsync(context, SR.GetResourceString(SR.ID8200));
        }

        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));

        headers.Set("Content-Security-Policy", OpenIddictServerSamlLogoutService.CreateLogoutContentSecurityPolicy(action, nonce));
        context.Response.ContentType = "text/html; charset=utf-8";

        return WriteAsync(context, OpenIddictServerSamlLogoutService.CreateLogoutPage(action, nonce));
    }

    private static async Task WriteResponseAsync(IOwinContext context, OpenIddictServerSamlService service,
        AuthenticationRequestResult result, string response, Func<Task<bool>> consumeRequestStateAsync)
    {
        var url = result.AssertionConsumerServiceUrl!;

        // When the HTTP-Artifact binding is used, the response is stored and the user agent is redirected to
        // the assertion consumer service with the artifact representing it (SAML bindings, 3.6.3.2 and 3.6.5).
        if (result.ResponseBinding is Bindings.HttpArtifact)
        {
            var artifact = await service.CreateArtifactAsync(result.ServiceProvider!, response, context.Request.CallCancelled);

            if (!await consumeRequestStateAsync())
            {
                return;
            }

            context.Response.StatusCode = 303;
            context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
            context.Response.Headers.Set("Pragma", "no-cache");
            context.Response.Headers.Set("Location", OpenIddictServerSamlService.CreateArtifactRedirectUrl(
                url, artifact, result.RelayState).AbsoluteUri);
            return;
        }

        if (!await consumeRequestStateAsync())
        {
            return;
        }

        var nonce = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(16));

        var headers = context.Response.Headers;
        headers.Set("Cache-Control", "no-cache, no-store");
        headers.Set("Pragma", "no-cache");
        headers.Set("Content-Security-Policy", $"default-src 'none'; script-src 'nonce-{nonce}'; " +
            $"form-action {url.GetLeftPart(UriPartial.Authority)}; frame-ancestors 'none'; base-uri 'none'");

        context.Response.ContentType = "text/html; charset=utf-8";

        await WriteAsync(context, OpenIddictServerSamlService.CreateFormPostPage(url, response, result.RelayState, nonce));
    }

    private static Task WriteErrorAsync(IOwinContext context, string description)
    {
        context.Response.StatusCode = 400;
        context.Response.Headers.Set("Cache-Control", "no-cache, no-store");
        context.Response.ContentType = "text/plain; charset=utf-8";

        return WriteAsync(context, description);
    }

    private static Task WriteAsync(IOwinContext context, string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        context.Response.ContentLength = bytes.Length;

        return context.Response.WriteAsync(bytes, context.Request.CallCancelled);
    }

    private static OpenIddictServerSamlService GetService(IServiceProvider provider)
        => provider.GetService<OpenIddictServerSamlService>() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0578));

    private static bool IsGet(IOwinRequest request) => string.Equals(request.Method, "GET", StringComparison.OrdinalIgnoreCase);

    private static bool IsPost(IOwinRequest request) => string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase);

    private static bool ValidateTransportSecurity(IOwinContext context, OpenIddictServerSamlOwinOptions options)
        => options.DisableTransportSecurityRequirement || context.Request.IsSecure;

    /// <summary>
    /// Gets the absolute base URI of the current request (built the same way as by the OpenIddict server OWIN host).
    /// </summary>
    internal static Uri? GetBaseUri(IOwinContext context)
        => Uri.TryCreate(context.Request.Scheme + Uri.SchemeDelimiter + context.Request.Host.Value + context.Request.PathBase,
            UriKind.Absolute, out var uri) ? uri : null;

    private static Uri GetEndpointUrl(IOwinContext context, PathString path)
        => new(context.Request.Scheme + Uri.SchemeDelimiter + context.Request.Host.Value +
            context.Request.PathBase.Add(path).ToUriComponent(), UriKind.Absolute);
}
