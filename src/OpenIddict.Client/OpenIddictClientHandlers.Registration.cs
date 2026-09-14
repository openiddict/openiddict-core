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
    public static class Registration
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Registration response handling:
             */
            ValidateWellKnownParameters.Descriptor,
            HandleErrorResponse.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the registration response.
        /// </summary>
        public sealed class ValidateWellKnownParameters : IOpenIddictClientHandler<HandleRegistrationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleRegistrationResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleRegistrationResponseContext context)
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

                // See https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.1 for more information.
                static bool ValidateParameterType(string name, OpenIddictParameter value) => name switch
                {
                    // The following parameters MUST be formatted as unique strings:
                    Parameters.Error or Parameters.ErrorDescription or Parameters.ErrorUri or
                    ClientMetadata.ClientId or ClientMetadata.ClientSecret or
                    ClientMetadata.RegistrationAccessToken or ClientMetadata.RegistrationClientUri
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as numeric dates:
                    ClientMetadata.ClientIdIssuedAt or ClientMetadata.ClientSecretExpiresAt
                        => ((JsonElement) value).ValueKind is JsonValueKind.Number,

                    // Other metadata can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the registration response.
        /// </summary>
        public sealed class HandleErrorResponse : IOpenIddictClientHandler<HandleRegistrationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleRegistrationResponseContext>()
                    .UseSingletonHandler<HandleErrorResponse>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleRegistrationResponseContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(6612, SR.GetResourceString(SR.ID6612), context.Response);

                    // Note: the standard registration errors are preserved to allow the caller to determine
                    // why the registration was rejected (e.g because a redirect URI was not accepted).
                    //
                    // See https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2 for more information.
                    context.Reject(
                        error: context.Response.Error switch
                        {
                            Errors.InvalidClientMetadata       or Errors.InvalidRedirectUri or
                            Errors.InvalidSoftwareStatement    or Errors.UnapprovedSoftwareStatement or
                            Errors.InvalidToken                or Errors.InsufficientScope or
                            Errors.InsufficientAccess          or Errors.InvalidRequest
                                => context.Response.Error,

                            _ => Errors.ServerError
                        },
                        description: SR.GetResourceString(SR.ID2415),
                        uri: SR.FormatID8000(SR.ID2415));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }
    }
}
