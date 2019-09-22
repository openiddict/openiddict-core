/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlerFilters;
using Properties = OpenIddict.Server.OpenIddictServerConstants.Properties;

namespace OpenIddict.Server
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictServerHandlers
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            AttachAmbientPrincipal.Descriptor,

            /*
             * Challenge processing:
             */
            AttachDefaultChallengeError.Descriptor,
            
            /*
            * Sign-in processing:
            */
            ValidateSigninResponse.Descriptor,
            AttachDefaultScopes.Descriptor,
            AttachDefaultPresenters.Descriptor,
            InferResources.Descriptor,
            EvaluateReturnedTokens.Descriptor,
            AttachAuthorization.Descriptor,
            AttachAccessToken.Descriptor,
            AttachAuthorizationCode.Descriptor,
            AttachRefreshToken.Descriptor,
            AttachIdentityToken.Descriptor)

            .AddRange(Authentication.DefaultHandlers)
            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Exchange.DefaultHandlers)
            .AddRange(Introspection.DefaultHandlers)
            .AddRange(Revocation.DefaultHandlers)
            .AddRange(Serialization.DefaultHandlers)
            .AddRange(Session.DefaultHandlers)
            .AddRange(Userinfo.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of attaching the ambient principal resolved for the current request.
        /// </summary>
        public class AttachAmbientPrincipal : IOpenIddictServerHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<AttachAmbientPrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessAuthenticationContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Logout:
                    case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                    case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                    case OpenIddictServerEndpointType.Userinfo:
                    {
                        if (context.Transaction.Properties.TryGetValue(Properties.AmbientPrincipal, out var principal))
                        {
                            context.Principal = (ClaimsPrincipal) principal;
                        }

                        return default;
                    }

                    default: throw new InvalidOperationException("An identity cannot be extracted from this request.");
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the challenge response contains an appropriate error.
        /// </summary>
        public class AttachDefaultChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .UseSingletonHandler<AttachDefaultChallengeError>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessChallengeContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Response.Error = context.EndpointType switch
                    {
                        OpenIddictServerEndpointType.Authorization => Errors.AccessDenied,
                        OpenIddictServerEndpointType.Token         => Errors.InvalidGrant,
                        OpenIddictServerEndpointType.Userinfo      => Errors.InvalidToken,

                        _ => throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.")
                    };
                }

                if (string.IsNullOrEmpty(context.Response.ErrorDescription))
                {
                    context.Response.ErrorDescription = context.EndpointType switch
                    {
                        OpenIddictServerEndpointType.Authorization => "The authorization was denied by the resource owner.",
                        OpenIddictServerEndpointType.Token         => "The token request was rejected by the authorization server.",
                        OpenIddictServerEndpointType.Userinfo      => "The access token is not valid or cannot be used to retrieve user information.",

                        _ => throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.")
                    };
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the sign-in response
        /// is compatible with the type of the endpoint that handled the request.
        /// </summary>
        public class ValidateSigninResponse : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<ValidateSigninResponse>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                switch (context.EndpointType)
                {
                    case OpenIddictServerEndpointType.Authorization:
                    case OpenIddictServerEndpointType.Token:
                        break;

                    default: throw new InvalidOperationException("An OpenID Connect response cannot be returned from this endpoint.");
                }

                if (context.Principal.Identity == null || !context.Principal.Identity.IsAuthenticated)
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The specified principal doesn't contain a valid or authenticated identity.")
                        .Append("Make sure that both 'ClaimsPrincipal.Identity' and 'ClaimsPrincipal.Identity.AuthenticationType' ")
                        .Append("are not null and that 'ClaimsPrincipal.Identity.IsAuthenticated' returns 'true'.")
                        .ToString());
                }

                if (string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                {
                    throw new InvalidOperationException(new StringBuilder()
                        .AppendLine("The security principal was rejected because the mandatory subject claim was missing.")
                        .ToString());
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching default scopes to the authentication principal.
        /// </summary>
        public class AttachDefaultScopes : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<AttachDefaultScopes>()
                    .SetOrder(ValidateSigninResponse.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
                // Note: the application is allowed to specify a different "scopes": in this case,
                // don't replace the "scopes" property stored in the authentication ticket.
                if (!context.Principal.HasScope() && context.Request.HasScope(Scopes.OpenId))
                {
                    context.Principal.SetScopes(Scopes.OpenId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching default presenters to the authentication principal.
        /// </summary>
        public class AttachDefaultPresenters : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<AttachDefaultPresenters>()
                    .SetOrder(AttachDefaultScopes.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Add the validated client_id to the list of authorized presenters,
                // unless the presenters were explicitly set by the developer.
                if (!context.Principal.HasPresenter() && !string.IsNullOrEmpty(context.ClientId))
                {
                    context.Principal.SetPresenters(context.ClientId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of inferring resources from the audience claims if necessary.
        /// </summary>
        public class InferResources : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<InferResources>()
                    .SetOrder(AttachDefaultPresenters.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // When a "resources" property cannot be found in the ticket, infer it from the "audiences" property.
                if (context.Principal.HasAudience() && !context.Principal.HasResource())
                {
                    context.Principal.SetResources(context.Principal.GetAudiences());
                }

                // Reset the audiences collection, as it's later set, based on the token type.
                context.Principal.SetAudiences(Array.Empty<string>());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of selecting the token types returned to the client application.
        /// </summary>
        public class EvaluateReturnedTokens : IOpenIddictServerHandler<ProcessSigninContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .UseSingletonHandler<EvaluateReturnedTokens>()
                    .SetOrder(InferResources.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.IncludeAccessToken = context.EndpointType switch
                {
                    // For authorization requests, return an access token if a response type containing token was specified.
                    OpenIddictServerEndpointType.Authorization => context.Request.HasResponseType(ResponseTypes.Token),

                    // For token requests, always return an access token.
                    OpenIddictServerEndpointType.Token => true,

                    _ => false
                };

                context.IncludeAuthorizationCode = context.EndpointType switch
                {
                    // For authorization requests, return an authorization code if a response type containing code was specified.
                    OpenIddictServerEndpointType.Authorization => context.Request.HasResponseType(ResponseTypes.Code),

                    // For token requests, prevent an authorization code from being returned as this type of token
                    // cannot be issued from the token endpoint in the standard OAuth 2.0/OpenID Connect flows.
                    OpenIddictServerEndpointType.Token => false,

                    _ => false
                };

                context.IncludeRefreshToken = context.EndpointType switch
                {
                    // For authorization requests, prevent a refresh token from being returned as OAuth 2.0
                    // explicitly disallows returning a refresh token from the authorization endpoint.
                    // See https://tools.ietf.org/html/rfc6749#section-4.2.2 for more information.
                    OpenIddictServerEndpointType.Authorization => false,

                    // For token requests, don't return a refresh token is the offline_access scope was not granted.
                    OpenIddictServerEndpointType.Token when !context.Principal.HasScope(Scopes.OfflineAccess) => false,

                    // For token requests, only return a refresh token is the offline_access scope was granted and
                    // if sliding expiration is disabled or if the request is not a grant_type=refresh_token request.
                    OpenIddictServerEndpointType.Token => context.Options.UseSlidingExpiration ||
                                                         !context.Request.IsRefreshTokenGrantType(),

                    _ => false
                };

                context.IncludeIdentityToken = context.EndpointType switch
                {
                    // For authorization requests, return an identity token if a response type containing code
                    // was specified and if the openid scope was explicitly or implicitly granted.
                    OpenIddictServerEndpointType.Authorization => context.Principal.HasScope(Scopes.OpenId) &&
                                                                  context.Request.HasResponseType(ResponseTypes.IdToken),

                    // For token requests, only return an identity token if the openid scope was granted.
                    OpenIddictServerEndpointType.Token => context.Principal.HasScope(Scopes.OpenId),

                    _ => false
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of creating an ad-hoc authorization, if necessary.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public class AttachAuthorization : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;
            private readonly IOpenIddictAuthorizationManager _authorizationManager;

            public AttachAuthorization() => throw new InvalidOperationException(new StringBuilder()
                .AppendLine("The core services must be registered when enabling the OpenIddict server feature.")
                .Append("To register the OpenIddict core services, reference the 'OpenIddict.Core' package ")
                .AppendLine("and call 'services.AddOpenIddict().AddCore()' from 'ConfigureServices'.")
                .Append("Alternatively, you can disable the built-in database-based server features by enabling ")
                .Append("the degraded mode with 'services.AddOpenIddict().AddServer().EnableDegradedMode()'.")
                .ToString());

            public AttachAuthorization(
                [NotNull] IOpenIddictApplicationManager applicationManager,
                [NotNull] IOpenIddictAuthorizationManager authorizationManager)
            {
                _applicationManager = applicationManager;
                _authorizationManager = authorizationManager;
            }

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequireAuthorizationStorageEnabled>()
                    .UseScopedHandler<AttachAuthorization>()
                    .SetOrder(EvaluateReturnedTokens.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If no authorization code or refresh token is returned, don't create an authorization.
                if (!context.IncludeAuthorizationCode && !context.IncludeRefreshToken)
                {
                    return;
                }

                // If an authorization identifier was explicitly specified, don't create an ad-hoc authorization.
                if (!string.IsNullOrEmpty(context.Principal.GetInternalAuthorizationId()))
                {
                    return;
                }

                var descriptor = new OpenIddictAuthorizationDescriptor
                {
                    Principal = context.Principal,
                    Status = Statuses.Valid,
                    Subject = context.Principal.GetClaim(Claims.Subject),
                    Type = AuthorizationTypes.AdHoc
                };

                descriptor.Scopes.UnionWith(context.Principal.GetScopes());

                // If the client application is known, associate it to the authorization.
                if (!string.IsNullOrEmpty(context.Request.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId);
                    if (application == null)
                    {
                        throw new InvalidOperationException("The application entry cannot be found in the database.");
                    }

                    descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
                }

                var authorization = await _authorizationManager.CreateAsync(descriptor);
                if (authorization == null)
                {
                    return;
                }

                var identifier = await _authorizationManager.GetIdAsync(authorization);

                if (string.IsNullOrEmpty(context.Request.ClientId))
                {
                    context.Logger.LogInformation("An ad hoc authorization was automatically created and " +
                                                  "associated with an unknown application: {Identifier}.", identifier);
                }

                else
                {
                    context.Logger.LogInformation("An ad hoc authorization was automatically created and " +
                                                  "associated with the '{ClientId}' application: {Identifier}.",
                                                  context.Request.ClientId, identifier);
                }

                // Attach the unique identifier of the ad hoc authorization to the authentication principal
                // so that it is attached to all the derived tokens, allowing batched revocations support.
                context.Principal.SetInternalAuthorizationId(identifier);
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching an access token.
        /// </summary>
        public class AttachAccessToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictServerProvider _provider;

            public AttachAccessToken([NotNull] IOpenIddictServerProvider provider)
                => _provider = provider;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAccessTokenIncluded>()
                    .UseScopedHandler<AttachAccessToken>()
                    .SetOrder(AttachAuthorization.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Create a new principal containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never exclude the subject claim.
                    if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Always exclude private claims, whose values must generally be kept secret.
                    if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Claims whose destination is not explicitly referenced or doesn't
                    // contain "access_token" are not included in the access token.
                    if (!claim.HasDestination(Destinations.AccessToken))
                    {
                        context.Logger.LogDebug("'{Claim}' was excluded from the access token claims.", claim.Type);

                        return false;
                    }

                    return true;
                });

                // Remove the destinations from the claim properties.
                foreach (var claim in principal.Claims)
                {
                    claim.Properties.Remove(OpenIddictConstants.Properties.Destinations);
                }

                principal.SetPublicTokenId(Guid.NewGuid().ToString()).SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetAccessTokenLifetime() ?? context.Options.AccessTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Set the audiences collection using the private resource claims stored in the principal.
                principal.SetAudiences(context.Principal.GetResources());

                // When receiving a grant_type=refresh_token request, determine whether the client application
                // requests a limited set of scopes and immediately replace the scopes collection if necessary.
                if (context.EndpointType == OpenIddictServerEndpointType.Token &&
                    context.Request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(context.Request.Scope))
                {
                    var scopes = context.Request.GetScopes();
                    if (scopes.Count != 0)
                    {
                        context.Logger.LogDebug("The access token scopes will be limited to the scopes " +
                                                "requested by the client application: {Scopes}.", scopes);

                        principal.SetScopes(scopes.Intersect(context.Principal.GetScopes()));
                    }
                }

                var notification = new SerializeAccessTokenContext(context.Transaction)
                {
                    Principal = principal
                };

                await _provider.DispatchAsync(notification);

                context.Response.TokenType = TokenTypes.Bearer;
                context.Response.AccessToken = notification.Token;

                // If an expiration date was set, return it to the client application.
                var date = notification.Principal.GetExpirationDate();
                if (date.HasValue && date.Value > DateTimeOffset.UtcNow)
                {
                    context.Response.ExpiresIn = (long) ((date.Value - DateTimeOffset.UtcNow).TotalSeconds + .5);
                }

                // If the granted scopes differ from the request scopes, return the granted scopes list as a parameter.
                if (context.Request.IsAuthorizationCodeGrantType() ||
                   !context.Principal.GetScopes().SetEquals(context.Request.GetScopes()))
                {
                    context.Response.Scope = string.Join(" ", context.Principal.GetScopes());
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching an authorization code.
        /// </summary>
        public class AttachAuthorizationCode : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictServerProvider _provider;

            public AttachAuthorizationCode([NotNull] IOpenIddictServerProvider provider)
                => _provider = provider;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireAuthorizationCodeIncluded>()
                    .UseScopedHandler<AttachAuthorizationCode>()
                    .SetOrder(AttachAccessToken.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.Principal.Clone(_ => true)
                    .SetPublicTokenId(Guid.NewGuid().ToString())
                    .SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetAuthorizationCodeLifetime() ?? context.Options.AuthorizationCodeLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                // Attach the redirect_uri to allow for later comparison when
                // receiving a grant_type=authorization_code token request.
                if (!string.IsNullOrEmpty(context.Request.RedirectUri))
                {
                    principal.SetClaim(Claims.Private.RedirectUri, context.Request.RedirectUri);
                }

                // Attach the code challenge and the code challenge methods to allow the ValidateCodeVerifier
                // handler to validate the code verifier sent by the client as part of the token request.
                if (!string.IsNullOrEmpty(context.Request.CodeChallenge))
                {
                    principal.SetClaim(Claims.Private.CodeChallenge, context.Request.CodeChallenge);

                    // Default to S256 if no explicit code challenge method was specified.
                    principal.SetClaim(Claims.Private.CodeChallengeMethod,
                        !string.IsNullOrEmpty(context.Request.CodeChallengeMethod) ?
                        context.Request.CodeChallengeMethod : CodeChallengeMethods.Sha256);
                }

                // Attach the nonce so that it can be later returned by
                // the token endpoint as part of the JWT identity token.
                if (!string.IsNullOrEmpty(context.Request.Nonce))
                {
                    principal.SetClaim(Claims.Private.Nonce, context.Request.Nonce);
                }

                var notification = new SerializeAuthorizationCodeContext(context.Transaction)
                {
                    Principal = principal
                };

                await _provider.DispatchAsync(notification);

                context.Response.Code = notification.Token;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching a refresh token.
        /// </summary>
        public class AttachRefreshToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictServerProvider _provider;

            public AttachRefreshToken([NotNull] IOpenIddictServerProvider provider)
                => _provider = provider;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireRefreshTokenIncluded>()
                    .UseScopedHandler<AttachRefreshToken>()
                    .SetOrder(AttachAuthorizationCode.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var principal = context.Principal.Clone(_ => true)
                    .SetPublicTokenId(Guid.NewGuid().ToString())
                    .SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetRefreshTokenLifetime() ?? context.Options.RefreshTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                var notification = new SerializeRefreshTokenContext(context.Transaction)
                {
                    Principal = principal
                };

                await _provider.DispatchAsync(notification);

                context.Response.RefreshToken = notification.Token;
            }
        }

        /// <summary>
        /// Contains the logic responsible of generating and attaching an identity token.
        /// </summary>
        public class AttachIdentityToken : IOpenIddictServerHandler<ProcessSigninContext>
        {
            private readonly IOpenIddictServerProvider _provider;

            public AttachIdentityToken([NotNull] IOpenIddictServerProvider provider)
                => _provider = provider;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSigninContext>()
                    .AddFilter<RequireIdentityTokenIncluded>()
                    .UseScopedHandler<AttachIdentityToken>()
                    .SetOrder(AttachRefreshToken.Descriptor.Order + 1_000)
                    .Build();

            /// <summary>
            /// Processes the event.
            /// </summary>
            /// <param name="context">The context associated with the event to process.</param>
            /// <returns>
            /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
            /// </returns>
            public async ValueTask HandleAsync([NotNull] ProcessSigninContext context)
            {
                if (context == null)
                {
                    throw new ArgumentNullException(nameof(context));
                }


                // Replace the principal by a new one containing only the filtered claims.
                // Actors identities are also filtered (delegation scenarios).
                var principal = context.Principal.Clone(claim =>
                {
                    // Never exclude the subject claim.
                    if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    // Always exclude private claims, whose values must generally be kept secret.
                    if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }

                    // Claims whose destination is not explicitly referenced or doesn't
                    // contain "id_token" are not included in the identity token.
                    if (!claim.HasDestination(Destinations.IdentityToken))
                    {
                        context.Logger.LogDebug("'{Claim}' was excluded from the identity token claims.", claim.Type);

                        return false;
                    }

                    return true;
                });

                // Remove the destinations from the claim properties.
                foreach (var claim in principal.Claims)
                {
                    claim.Properties.Remove(OpenIddictConstants.Properties.Destinations);
                }

                principal.SetPublicTokenId(Guid.NewGuid().ToString()).SetCreationDate(DateTimeOffset.UtcNow);

                var lifetime = context.Principal.GetIdentityTokenLifetime() ?? context.Options.IdentityTokenLifetime;
                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }

                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    principal.SetAudiences(context.ClientId);
                }

                // If a nonce was present in the authorization request, it MUST be included in the id_token generated
                // by the token endpoint. For that, OpenIddict simply flows the nonce as an authorization code claim.
                // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.

                if (context.EndpointType == OpenIddictServerEndpointType.Authorization && !string.IsNullOrEmpty(context.Request.Nonce))
                {
                    principal.SetClaim(Claims.Nonce, context.Request.Nonce);
                }

                else if (context.EndpointType == OpenIddictServerEndpointType.Token)
                {
                    var nonce = context.Principal.GetClaim(Claims.Private.Nonce);
                    if (!string.IsNullOrEmpty(nonce))
                    {
                        principal.SetClaim(Claims.Nonce, nonce);
                    }
                }

                if (!string.IsNullOrEmpty(context.Response.AccessToken) || !string.IsNullOrEmpty(context.Response.Code))
                {
                    var credentials = context.Options.SigningCredentials.FirstOrDefault(
                        credentials => credentials.Key is AsymmetricSecurityKey);
                    if (credentials == null)
                    {
                        throw new InvalidOperationException("No suitable signing credentials could be found.");
                    }

                    using var hash = GetHashAlgorithm(credentials);
                    if (hash == null || hash is KeyedHashAlgorithm)
                    {
                        throw new InvalidOperationException("The signing credentials algorithm is not valid.");
                    }

                    if (!string.IsNullOrEmpty(context.Response.Code))
                    {
                        var digest = hash.ComputeHash(Encoding.ASCII.GetBytes(context.Response.Code));

                        // Note: only the left-most half of the hash is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                        principal.SetClaim(Claims.CodeHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
                    }

                    if (!string.IsNullOrEmpty(context.Response.AccessToken))
                    {
                        var digest = hash.ComputeHash(Encoding.ASCII.GetBytes(context.Response.AccessToken));

                        // Note: only the left-most half of the hash is used.
                        // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                        principal.SetClaim(Claims.AccessTokenHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
                    }
                }

                var notification = new SerializeIdentityTokenContext(context.Transaction)
                {
                    Principal = principal
                };

                await _provider.DispatchAsync(notification);

                context.Response.IdToken = notification.Token;

                static HashAlgorithm GetHashAlgorithm(SigningCredentials credentials)
                {
                    HashAlgorithm hash = null;

                    if (!string.IsNullOrEmpty(credentials.Digest))
                    {
                        hash = CryptoConfig.CreateFromName(credentials.Digest) as HashAlgorithm;
                    }

                    if (hash == null)
                    {
                        var algorithm = credentials.Digest switch
                        {
                            SecurityAlgorithms.Sha256 => HashAlgorithmName.SHA256,
                            SecurityAlgorithms.Sha384 => HashAlgorithmName.SHA384,
                            SecurityAlgorithms.Sha512 => HashAlgorithmName.SHA512,
                            SecurityAlgorithms.Sha256Digest => HashAlgorithmName.SHA256,
                            SecurityAlgorithms.Sha384Digest => HashAlgorithmName.SHA384,
                            SecurityAlgorithms.Sha512Digest => HashAlgorithmName.SHA512,

                            _ => credentials.Algorithm switch
                            {
#if SUPPORTS_ECDSA
                                SecurityAlgorithms.EcdsaSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.EcdsaSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.EcdsaSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.EcdsaSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.EcdsaSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.EcdsaSha512Signature => HashAlgorithmName.SHA512,
#endif
                                SecurityAlgorithms.HmacSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.HmacSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.HmacSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.HmacSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.HmacSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.HmacSha512Signature => HashAlgorithmName.SHA512,

                                SecurityAlgorithms.RsaSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.RsaSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSha512Signature => HashAlgorithmName.SHA512,

                                SecurityAlgorithms.RsaSsaPssSha256 => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSsaPssSha384 => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSsaPssSha512 => HashAlgorithmName.SHA512,
                                SecurityAlgorithms.RsaSsaPssSha256Signature => HashAlgorithmName.SHA256,
                                SecurityAlgorithms.RsaSsaPssSha384Signature => HashAlgorithmName.SHA384,
                                SecurityAlgorithms.RsaSsaPssSha512Signature => HashAlgorithmName.SHA512,

                                _ => throw new InvalidOperationException("The signing credentials algorithm is not supported.")
                            }
                        };

                        hash = CryptoConfig.CreateFromName(algorithm.Name) as HashAlgorithm;
                    }

                    return hash;
                }
            }
        }
    }
}
