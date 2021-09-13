/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Immutable;
using System.ComponentModel;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlerFilters;
using SR = OpenIddict.Abstractions.OpenIddictResources;

namespace OpenIddict.Validation
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static partial class OpenIddictValidationHandlers
    {
        public static ImmutableArray<OpenIddictValidationHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authentication processing:
             */
            EvaluateValidatedTokens.Descriptor,
            ValidateAccessToken.Descriptor,

            /*
             * Challenge processing:
             */
            AttachDefaultChallengeError.Descriptor)

            .AddRange(Discovery.DefaultHandlers)
            .AddRange(Introspection.DefaultHandlers)
            .AddRange(Protection.DefaultHandlers);

        /// <summary>
        /// Contains the logic responsible of selecting the token types that should be validated.
        /// </summary>
        public class EvaluateValidatedTokens : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .UseSingletonHandler<EvaluateValidatedTokens>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                (context.ValidateAccessToken, context.RequireAccessToken) = context.EndpointType switch
                {
                    // The validation handler is responsible of validating access tokens for endpoints
                    // it doesn't manage (typically, API endpoints using token authentication).
                    //
                    // As such, sending an access token is not mandatory: API endpoints that require
                    // authentication can set up an authorization policy to reject such requests later
                    // in the request processing pipeline (typically, via the authorization middleware).
                    OpenIddictValidationEndpointType.Unknown => (true, false),

                    _ => (false, false)
                };

                // Note: unlike the equivalent event in the server stack, authentication can be triggered for
                // arbitrary requests (typically, API endpoints that are not owned by the validation stack).
                // As such, the token is not directly resolved from the request, that may be null at this stage.
                // Instead, the token is expected to be populated by one or multiple handlers provided by the host.

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring a token was correctly resolved from the context.
        /// </summary>
        public class ValidateAccessToken : IOpenIddictValidationHandler<ProcessAuthenticationContext>
        {
            private readonly IOpenIddictValidationDispatcher _dispatcher;

            public ValidateAccessToken(IOpenIddictValidationDispatcher dispatcher)
                => _dispatcher = dispatcher;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireAccessTokenValidated>()
                    .UseScopedHandler<ValidateAccessToken>()
                    .SetOrder(EvaluateValidatedTokens.Descriptor.Order + 1_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.AccessTokenPrincipal is not null)
                {
                    return;
                }

                if (string.IsNullOrEmpty(context.AccessToken))
                {
                    if (context.RequireAccessToken)
                    {
                        context.Reject(
                            error: Errors.MissingToken,
                            description: SR.GetResourceString(SR.ID2000),
                            uri: SR.FormatID8000(SR.ID2000));

                        return;
                    }

                    return;
                }

                var notification = new ValidateTokenContext(context.Transaction)
                {
                    Token = context.AccessToken,
                    ValidTokenTypes = { TokenTypeHints.AccessToken }
                };

                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                else if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                else if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.AccessTokenPrincipal = notification.Principal;
            }
        }

        /// <summary>
        /// Contains the logic responsible of ensuring that the challenge response contains an appropriate error.
        /// </summary>
        public class AttachDefaultChallengeError : IOpenIddictValidationHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .UseSingletonHandler<AttachDefaultChallengeError>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an error was explicitly set by the application, don't override it.
                if (!string.IsNullOrEmpty(context.Response.Error) ||
                    !string.IsNullOrEmpty(context.Response.ErrorDescription) ||
                    !string.IsNullOrEmpty(context.Response.ErrorUri))
                {
                    return default;
                }

                // Try to retrieve the authentication context from the validation transaction and use
                // the error details returned during the authentication processing, if available.
                // If no error is attached to the authentication context, this likely means that
                // the request was rejected very early without even checking the access token or was
                // rejected due to a lack of permission. In this case, return an insufficient_access error
                // to inform the client that the user is not allowed to perform the requested action.

                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName!);

                if (!string.IsNullOrEmpty(notification?.Error))
                {
                    context.Response.Error = notification.Error;
                    context.Response.ErrorDescription = notification.ErrorDescription;
                    context.Response.ErrorUri = notification.ErrorUri;
                }

                else
                {
                    context.Response.Error = Errors.InsufficientAccess;
                    context.Response.ErrorDescription = SR.GetResourceString(SR.ID2095);
                    context.Response.ErrorUri = SR.FormatID8000(SR.ID2095);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of attaching the appropriate parameters to the error response.
        /// </summary>
        public class AttachErrorParameters : IOpenIddictValidationHandler<ProcessErrorContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                    .UseSingletonHandler<AttachErrorParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessErrorContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Response.Error = context.Error;
                context.Response.ErrorDescription = context.ErrorDescription;
                context.Response.ErrorUri = context.ErrorUri;

                if (context.Parameters.Count > 0)
                {
                    foreach (var parameter in context.Parameters)
                    {
                        context.Response.SetParameter(parameter.Key, parameter.Value);
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible of extracting potential errors from the response.
        /// </summary>
        public class HandleErrorResponse<TContext> : IOpenIddictValidationHandler<TContext> where TContext : BaseValidatingContext
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictValidationHandlerDescriptor Descriptor { get; }
                = OpenIddictValidationHandlerDescriptor.CreateBuilder<TContext>()
                    .UseSingletonHandler<HandleErrorResponse<TContext>>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictValidationHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (!string.IsNullOrEmpty(context.Transaction.Response?.Error))
                {
                    context.Reject(
                        error: context.Transaction.Response.Error,
                        description: context.Transaction.Response.ErrorDescription,
                        uri: context.Transaction.Response.ErrorUri);

                    return default;
                }

                return default;
            }
        }
    }
}
