/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using OpenIddict.Extensions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Device
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Token response extraction:
             */
            MapNonStandardResponseParameters.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for mapping non-standard response parameters
        /// to their standard equivalent for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardResponseParameters : IOpenIddictClientHandler<ExtractDeviceAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractDeviceAuthorizationResponseContext>()
                    .UseSingletonHandler<MapNonStandardResponseParameters>()
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractDeviceAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Response is null)
                {
                    return default;
                }

                // Note: Google doesn't return a standard "verification_uri" parameter
                // but returns a custom "verification_url" that serves the same purpose.
                if (context.Registration.ProviderType is ProviderTypes.Google)
                {
                    context.Response[Parameters.VerificationUri] = context.Response["verification_url"];
                    context.Response["verification_url"] = null;
                }

                // Note: Huawei returns a non-standard "error" parameter as a numeric value,
                // which is not allowed by OpenIddict (that requires a string).
                //
                // In device code responses, Huawei doesn't return a standard "verification_uri" parameter
                // but returns a custom "verification_url" that serves the same purpose. It also doesn't return
                // a standard "expires_in" parameter but returns a custom "expire_in" that serves the same purpose.
                else if (context.Registration.ProviderType is ProviderTypes.Huawei)
                {
                    if ((JsonElement?) context.Response[Parameters.Error] is { ValueKind: JsonValueKind.Number })
                    {
                        context.Response[Parameters.Error] = Errors.InvalidRequest;
                    }
                    else
                    {
                        var verificationUri = context.Response["verification_url"];
                        context.Response[Parameters.VerificationUri] = verificationUri;
                        if ((string?) verificationUri is { } verificationUriValue &&
                            !string.IsNullOrEmpty(context.Response.UserCode))
                        {
                            context.Response[Parameters.VerificationUriComplete] =
                                OpenIddictHelpers.AddQueryStringParameter(new Uri(verificationUriValue, UriKind.Absolute),
                                    Parameters.UserCode, context.Response.UserCode).AbsoluteUri;
                        }
                        context.Response["verification_url"] = null;

                        context.Response[Parameters.ExpiresIn] = context.Response["expire_in"];
                        context.Response["expire_in"] = null;
                    }
                }

                return default;
            }
        }
    }
}
