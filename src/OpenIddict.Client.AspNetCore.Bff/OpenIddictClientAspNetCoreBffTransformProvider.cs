/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;
using static OpenIddict.Client.AspNetCore.Bff.OpenIddictClientAspNetCoreBffModels;

namespace OpenIddict.Client.AspNetCore.Bff;

/// <summary>
/// Represents a YARP transform provider attaching the user or client access token to the requests
/// proxied through the routes whose <see cref="OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken"/>
/// metadata is set, and removing the cookies sent by the browser from these requests.
/// </summary>
public sealed class OpenIddictClientAspNetCoreBffTransformProvider : ITransformProvider
{
    /// <inheritdoc/>
    public void ValidateRoute(TransformRouteValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Route.Metadata?.TryGetValue(OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken, out var value) is true &&
            !OpenIddictClientAspNetCoreBffHelpers.TryParseTokenType(value, out _))
        {
            context.Errors.Add(new InvalidOperationException(SR.FormatID0562(
                OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken, context.Route.RouteId, value)));
        }
    }

    /// <inheritdoc/>
    public void ValidateCluster(TransformClusterValidationContext context)
    {
    }

    /// <inheritdoc/>
    public void Apply(TransformBuilderContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var metadata = context.Route.Metadata;
        if (metadata is null || !metadata.TryGetValue(OpenIddictClientAspNetCoreBffConstants.Metadata.AccessToken, out var value) ||
            !OpenIddictClientAspNetCoreBffHelpers.TryParseTokenType(value, out var type))
        {
            return;
        }

        // Never forward the cookies (that include the authentication cookie) to the remote API.
        context.AddRequestHeaderRemove(OpenIddictClientAspNetCoreBffConstants.Headers.Cookie);

        if (type is OpenIddictClientAspNetCoreBffTokenType.None)
        {
            return;
        }

        var request = new ClientAccessTokenRequest
        {
            RegistrationId = metadata.TryGetValue(OpenIddictClientAspNetCoreBffConstants.Metadata.RegistrationId, out var registration) &&
                !string.IsNullOrEmpty(registration) ? registration : null,
            Scopes = metadata.TryGetValue(OpenIddictClientAspNetCoreBffConstants.Metadata.Scopes, out var scopes) &&
                !string.IsNullOrEmpty(scopes) ? [.. scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries)] : null
        };

        context.AddRequestTransform(context => ApplyAccessTokenAsync(context, type, request));
    }

    /// <summary>
    /// Attaches the access token to the proxied request.
    /// </summary>
    /// <param name="context">The request transform context.</param>
    /// <param name="type">The type of access token.</param>
    /// <param name="request">The client access token request.</param>
    /// <returns>A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.</returns>
    internal static async ValueTask ApplyAccessTokenAsync(RequestTransformContext context,
        OpenIddictClientAspNetCoreBffTokenType type, ClientAccessTokenRequest request)
    {
        var manager = context.HttpContext.RequestServices.GetService<OpenIddictClientAspNetCoreBffTokenManager>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0561));

        // Note: the antiforgery and authentication checks are also enforced here so that the access tokens
        // are never attached to forged requests if the BFF middleware was not registered. Setting a non-200
        // status code prevents YARP from forwarding the request. The result of the checks is cached per request.
        if (!await OpenIddictClientAspNetCoreBffMiddleware.ValidateRequestAsync(context.HttpContext))
        {
            return;
        }

        // Remove the authorization header potentially sent by the browser.
        RequestTransform.RemoveHeader(context, HeaderNames.Authorization);

        var token = type switch
        {
            OpenIddictClientAspNetCoreBffTokenType.User or OpenIddictClientAspNetCoreBffTokenType.OptionalUser
                => await manager.GetUserAccessTokenAsync(context.HttpContext),

            OpenIddictClientAspNetCoreBffTokenType.Client
                => await manager.GetClientAccessTokenAsync(request, context.CancellationToken),

            OpenIddictClientAspNetCoreBffTokenType.UserOrClient
                => await manager.GetUserAccessTokenAsync(context.HttpContext) ??
                   await manager.GetClientAccessTokenAsync(request, context.CancellationToken),

            _ => null
        };

        if (token is null)
        {
            // Routes requiring a user access token are never proxied without one.
            if (type is OpenIddictClientAspNetCoreBffTokenType.User)
            {
                context.HttpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
            }

            return;
        }

        // Note: the request URI is computed by YARP after the request transforms are applied.
        var uri = context.ProxyRequest.RequestUri is { IsAbsoluteUri: true } value ? value :
            RequestUtilities.MakeDestinationAddress(context.DestinationPrefix, context.Path, context.Query.QueryString);

        await manager.AttachAccessTokenAsync(context.ProxyRequest, token, uri, cancellationToken: context.CancellationToken);
    }
}
