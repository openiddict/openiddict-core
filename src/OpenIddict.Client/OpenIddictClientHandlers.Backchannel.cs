/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Backchannel
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Backchannel authentication response handling:
             */
            ValidateWellKnownParameters.Descriptor,
            HandleErrorResponse.Descriptor,
            ValidateAuthenticationRequestId.Descriptor,
            ValidateExpiration.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the backchannel authentication response.
        /// </summary>
        public sealed class ValidateWellKnownParameters : IOpenIddictClientHandler<HandleBackchannelAuthenticationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleBackchannelAuthenticationResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleBackchannelAuthenticationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                foreach (var parameter in context.Response.GetParameters())
                {
                    if (!ValidateParameterType(parameter.Key, parameter.Value))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2107(parameter.Key),
                            uri: SR.FormatID8000(SR.ID2107));

                        return ValueTask.CompletedTask;
                    }
                }

                return ValueTask.CompletedTask;

                static bool ValidateParameterType(string name, OpenIddictParameter value) => name switch
                {
                    // The following parameters MUST be formatted as unique strings:
                    Parameters.AuthReqId or Parameters.Error or Parameters.ErrorDescription or Parameters.ErrorUri
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as positive numbers:
                    Parameters.ExpiresIn or Parameters.Interval
                        => (JsonElement) value is { ValueKind: JsonValueKind.Number } element &&
                            element.TryGetDecimal(out decimal result) && result is >= 0,

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the backchannel authentication response.
        /// </summary>
        public sealed class HandleErrorResponse : IOpenIddictClientHandler<HandleBackchannelAuthenticationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleBackchannelAuthenticationResponseContext>()
                    .UseSingletonHandler<HandleErrorResponse>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleBackchannelAuthenticationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // For more information, see
                // https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html#rfc.section.13.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(6306, SR.GetResourceString(SR.ID6306), context.Response);

                    context.Reject(
                        error: context.Response.Error switch
                        {
                            Errors.AccessDenied           => Errors.AccessDenied,
                            Errors.ExpiredLoginHintToken  => Errors.ExpiredLoginHintToken,
                            Errors.InvalidBindingMessage  => Errors.InvalidBindingMessage,
                            Errors.InvalidClient          => Errors.InvalidRequest,
                            Errors.InvalidRequest         => Errors.InvalidRequest,
                            Errors.InvalidScope           => Errors.InvalidScope,
                            Errors.InvalidUserCode        => Errors.InvalidUserCode,
                            Errors.MissingUserCode        => Errors.MissingUserCode,
                            Errors.UnauthorizedClient     => Errors.UnauthorizedClient,
                            Errors.UnknownUserId          => Errors.UnknownUserId,
                            _                             => Errors.ServerError
                        },
                        description: SR.GetResourceString(SR.ID2219),
                        uri: SR.FormatID8000(SR.ID2219));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the authentication
        /// request identifier contained in the backchannel authentication response.
        /// </summary>
        public sealed class ValidateAuthenticationRequestId : IOpenIddictClientHandler<HandleBackchannelAuthenticationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleBackchannelAuthenticationResponseContext>()
                    .UseSingletonHandler<ValidateAuthenticationRequestId>()
                    .SetOrder(HandleErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleBackchannelAuthenticationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Return an error if the mandatory "auth_req_id" parameter is missing.
                if (string.IsNullOrEmpty(context.Response.AuthReqId))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2168(Parameters.AuthReqId),
                        uri: SR.FormatID8000(SR.ID2168));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the "expires_in"
        /// parameter contained in the backchannel authentication response.
        /// </summary>
        public sealed class ValidateExpiration : IOpenIddictClientHandler<HandleBackchannelAuthenticationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleBackchannelAuthenticationResponseContext>()
                    .UseSingletonHandler<ValidateExpiration>()
                    .SetOrder(ValidateAuthenticationRequestId.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleBackchannelAuthenticationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Return an error if the mandatory "expires_in" parameter is missing.
                if (context.Response.ExpiresIn is null)
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2168(Parameters.ExpiresIn),
                        uri: SR.FormatID8000(SR.ID2168));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }
    }
}
