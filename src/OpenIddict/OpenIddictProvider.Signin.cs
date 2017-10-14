/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using OpenIddict.Core;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override async Task ProcessSigninResponse([NotNull] ProcessSigninResponseContext context)
        {
            var options = (OpenIddictOptions) context.Options;

            if (context.Request.IsTokenRequest() && (context.Request.IsAuthorizationCodeGrantType() ||
                                                     context.Request.IsRefreshTokenGrantType()))
            {
                // Note: when handling a grant_type=authorization_code or refresh_token request,
                // the OpenID Connect server middleware allows creating authentication tickets
                // that are completely disconnected from the original code or refresh token ticket.
                // This scenario is deliberately not supported in OpenIddict and all the tickets
                // must be linked. To ensure the properties are flowed from the authorization code
                // or the refresh token to the new ticket, they are manually restored if necessary.

                // Retrieve the original authentication ticket from the request properties.
                var ticket = context.Request.GetProperty<AuthenticationTicket>(
                    OpenIddictConstants.Properties.AuthenticationTicket);
                Debug.Assert(ticket != null, "The authentication ticket shouldn't be null.");

                // If the properties instances of the two authentication tickets differ,
                // restore the missing properties in the new authentication ticket.
                if (!ReferenceEquals(ticket.Properties, context.Ticket.Properties))
                {
                    foreach (var property in ticket.Properties.Items)
                    {
                        // Don't override the properties that have been
                        // manually set on the new authentication ticket.
                        if (context.Ticket.HasProperty(property.Key))
                        {
                            continue;
                        }

                        context.Ticket.AddProperty(property.Key, property.Value);
                    }

                    // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
                    // Note: the application is allowed to specify a different "scopes": in this case,
                    // don't replace the "scopes" property stored in the authentication ticket.
                    if (context.Request.HasScope(OpenIdConnectConstants.Scopes.OpenId) && !context.Ticket.HasScope())
                    {
                        context.Ticket.SetScopes(OpenIdConnectConstants.Scopes.OpenId);
                    }

                    context.IncludeIdentityToken = context.Ticket.HasScope(OpenIdConnectConstants.Scopes.OpenId);
                }

                context.IncludeRefreshToken = context.Ticket.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess);

                // Always include a refresh token for grant_type=refresh_token requests if
                // rolling tokens are enabled and if the offline_access scope was specified.
                if (context.Request.IsRefreshTokenGrantType())
                {
                    context.IncludeRefreshToken &= options.UseRollingTokens;
                }

                // If token revocation was explicitly disabled,
                // none of the following security routines apply.
                if (options.DisableTokenRevocation)
                {
                    return;
                }

                // If rolling tokens are enabled or if the request is a grant_type=authorization_code request,
                // mark the authorization code or the refresh token as redeemed to prevent future reuses.
                // See https://tools.ietf.org/html/rfc6749#section-6 for more information.
                if (options.UseRollingTokens || context.Request.IsAuthorizationCodeGrantType())
                {
                    if (!await TryRedeemTokenAsync(context.Ticket, context.HttpContext))
                    {
                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "The specified authorization code is no longer valid.");

                        return;
                    }
                }

                // When rolling tokens are enabled, revoke all the previously issued tokens associated
                // with the authorization if the request is a grant_type=refresh_token request.
                if (options.UseRollingTokens && context.Request.IsRefreshTokenGrantType())
                {
                    if (!await TryRevokeTokensAsync(context.Ticket, context.HttpContext))
                    {
                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "The specified refresh token is no longer valid.");

                        return;
                    }
                }

                // When rolling tokens are disabled, extend the expiration date
                // of the existing token instead of returning a new refresh token
                // with a new expiration date if sliding expiration was not disabled.
                else if (options.UseSlidingExpiration && context.Request.IsRefreshTokenGrantType())
                {
                    if (!await TryExtendTokenAsync(context.Ticket, context.HttpContext, options))
                    {
                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidGrant,
                            description: "The specified refresh token is no longer valid.");

                        return;
                    }

                    // Prevent the OpenID Connect server from returning a new refresh token.
                    context.IncludeRefreshToken = false;
                }
            }

            // If no authorization was explicitly attached to the authentication ticket,
            // create an ad hoc authorization if an authorization code or a refresh token
            // is going to be returned to the client application as part of the response.
            if (!context.Ticket.HasProperty(OpenIddictConstants.Properties.AuthorizationId) &&
                (context.IncludeAuthorizationCode || context.IncludeRefreshToken))
            {
                await CreateAuthorizationAsync(context.Ticket, options, context.HttpContext, context.Request);
            }
        }
    }
}