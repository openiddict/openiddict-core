/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    /// <summary>
    /// Contains the handlers enforcing the FAPI 2.0 security profile for client registrations
    /// (https://openid.net/specs/fapi-security-profile-2_0-final.html).
    /// </summary>
    public static class Fapi
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Authentication processing:
             */
            ValidateAuthorizationResponseIssuer.Descriptor,
            ValidateAuthenticationGrantType.Descriptor,
            ValidateTokenEndpointClientAuthenticationMethod.Descriptor,
            ValidateTokenEndpointTokenBindingMethod.Descriptor,

            /*
             * Challenge processing:
             */
            ValidateChallengeGrantType.Descriptor,
            ValidateCodeChallengeMethod.Descriptor,
            ValidateDeviceAuthorizationEndpointClientAuthenticationMethod.Descriptor,
            ValidateBackchannelAuthenticationEndpointClientAuthenticationMethod.Descriptor,
            ValidatePushedAuthorizationRequest.Descriptor,
            ValidatePushedAuthorizationEndpointClientAuthenticationMethod.Descriptor,

            /*
             * Introspection and revocation processing:
             */
            ValidateIntrospectionEndpointClientAuthenticationMethod.Descriptor,
            ValidateRevocationEndpointClientAuthenticationMethod.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for rejecting authorization responses that don't include an "iss"
        /// parameter matching the issuer of the client registration, even if issuer validation was disabled
        /// in the client options (section 5.3.3.2, item 7 and RFC 9207).
        /// </summary>
        public sealed class ValidateAuthorizationResponseIssuer : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateAuthorizationResponseIssuer>()
                    .SetOrder(ValidateIssuerParameter.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Authorization servers compliant with the profile always return the "iss" parameter
                // and must advertise it in their metadata: reject the response if they don't.
                if (context.Configuration.AuthorizationResponseIssParameterSupported is not true)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2486),
                        uri: SR.FormatID8000(SR.ID2486));

                    return ValueTask.CompletedTask;
                }

                var issuer = (string?) context.Request[Parameters.Iss];
                if (string.IsNullOrEmpty(issuer))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029(Parameters.Iss),
                        uri: SR.FormatID8000(SR.ID2029));

                    return ValueTask.CompletedTask;
                }

                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri) ||
                    OpenIddictHelpers.IsImplicitFileUri(uri) || uri != context.Registration.Issuer)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2119(Parameters.Iss),
                        uri: SR.FormatID8000(SR.ID2119));

                    return ValueTask.CompletedTask;
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authentication demands
        /// using the resource owner password credentials grant (section 5.3.2.1).
        /// </summary>
        public sealed class ValidateAuthenticationGrantType : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateAuthenticationGrantType>()
                    .SetOrder(EvaluateTokenRequest.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.GrantType is GrantTypes.Password or GrantTypes.Implicit)
                {
                    throw new InvalidOperationException(SR.FormatID0983(context.GrantType));
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring the client authentication method
        /// negotiated for the token endpoint is allowed by the profile (section 5.3.2.1, item 6).
        /// </summary>
        public sealed class ValidateTokenEndpointClientAuthenticationMethod : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireTokenRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateTokenEndpointClientAuthenticationMethod>()
                    .SetOrder(AttachTokenEndpointClientAuthenticationMethod.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                ValidateClientAuthenticationMethod(context.TokenEndpointClientAuthenticationMethod, Metadata.TokenEndpoint);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring the access tokens returned by the token
        /// endpoint are sender-constrained using DPoP or mTLS (section 5.3.3.1, item 2).
        /// </summary>
        public sealed class ValidateTokenEndpointTokenBindingMethod : IOpenIddictClientHandler<ProcessAuthenticationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                    .AddFilter<RequireTokenRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateTokenEndpointTokenBindingMethod>()
                    .SetOrder(AttachTokenEndpointTokenBindingMethod.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessAuthenticationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (string.IsNullOrEmpty(context.TokenEndpointTokenBindingMethod) ||
                    !OpenIddictClientFapi2Profile.TokenBindingMethods.Contains(context.TokenEndpointTokenBindingMethod, StringComparer.Ordinal))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0985));
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting challenges using the implicit, hybrid
        /// or response_type=none flows, as only response_type=code is allowed (section 5.3.2.2, item 1).
        /// </summary>
        public sealed class ValidateChallengeGrantType : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateChallengeGrantType>()
                    .SetOrder(AttachGrantTypeAndResponseType.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.GrantType is GrantTypes.Implicit or GrantTypes.Password)
                {
                    throw new InvalidOperationException(SR.FormatID0983(context.GrantType));
                }

                if (!string.IsNullOrEmpty(context.ResponseType) && context.ResponseType is not ResponseTypes.Code)
                {
                    throw new InvalidOperationException(SR.FormatID0983(context.ResponseType));
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring PKCE is used with the
        /// S256 code challenge method (section 5.3.3.1, item 1 and section 5.3.2.2, item 5).
        /// </summary>
        public sealed class ValidateCodeChallengeMethod : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireInteractiveGrantType>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateCodeChallengeMethod>()
                    .SetOrder(AttachCodeChallengeParameters.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (context.CodeChallengeMethod is not CodeChallengeMethods.Sha256 || string.IsNullOrEmpty(context.CodeChallenge))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0982));
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring the client authentication method negotiated
        /// for the device authorization endpoint is allowed by the profile (section 5.3.2.1, item 6).
        /// </summary>
        public sealed class ValidateDeviceAuthorizationEndpointClientAuthenticationMethod : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireDeviceAuthorizationRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateDeviceAuthorizationEndpointClientAuthenticationMethod>()
                    .SetOrder(AttachDeviceAuthorizationEndpointClientAuthenticationMethod.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                ValidateClientAuthenticationMethod(context.DeviceAuthorizationEndpointClientAuthenticationMethod,
                    Metadata.DeviceAuthorizationEndpoint);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring the client authentication method negotiated for
        /// the backchannel authentication endpoint is allowed by the profile (section 5.3.2.1, item 6).
        /// </summary>
        public sealed class ValidateBackchannelAuthenticationEndpointClientAuthenticationMethod : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireBackchannelAuthenticationRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateBackchannelAuthenticationEndpointClientAuthenticationMethod>()
                    .SetOrder(AttachBackchannelAuthenticationEndpointClientAuthenticationMethod.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                ValidateClientAuthenticationMethod(context.BackchannelAuthenticationEndpointClientAuthenticationMethod,
                    Metadata.BackchannelAuthenticationEndpoint);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring interactive challenges are
        /// sent as pushed authorization requests (section 5.3.2.2, item 5).
        /// </summary>
        public sealed class ValidatePushedAuthorizationRequest : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireInteractiveGrantType>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidatePushedAuthorizationRequest>()
                    .SetOrder(EvaluatePushedAuthorizationRequest.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                if (!context.SendPushedAuthorizationRequest)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0981));
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring the client authentication method negotiated for
        /// the pushed authorization endpoint is allowed by the profile (section 5.3.2.1, item 6).
        /// </summary>
        public sealed class ValidatePushedAuthorizationEndpointClientAuthenticationMethod : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequirePushedAuthorizationRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidatePushedAuthorizationEndpointClientAuthenticationMethod>()
                    .SetOrder(AttachPushedAuthorizationEndpointClientAuthenticationMethod.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessChallengeContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                ValidateClientAuthenticationMethod(context.PushedAuthorizationEndpointClientAuthenticationMethod,
                    Metadata.PushedAuthorizationRequestEndpoint);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring the client authentication method negotiated
        /// for the introspection endpoint is allowed by the profile (section 5.3.2.1, item 6).
        /// </summary>
        public sealed class ValidateIntrospectionEndpointClientAuthenticationMethod : IOpenIddictClientHandler<ProcessIntrospectionContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessIntrospectionContext>()
                    .AddFilter<RequireIntrospectionRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateIntrospectionEndpointClientAuthenticationMethod>()
                    .SetOrder(AttachIntrospectionEndpointClientAuthenticationMethod.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessIntrospectionContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                ValidateClientAuthenticationMethod(context.IntrospectionEndpointClientAuthenticationMethod,
                    Metadata.IntrospectionEndpoint);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for ensuring the client authentication method negotiated
        /// for the revocation endpoint is allowed by the profile (section 5.3.2.1, item 6).
        /// </summary>
        public sealed class ValidateRevocationEndpointClientAuthenticationMethod : IOpenIddictClientHandler<ProcessRevocationContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRevocationContext>()
                    .AddFilter<RequireRevocationRequest>()
                    .AddFilter<RequireFapi2SecurityProfileEnabled>()
                    .UseSingletonHandler<ValidateRevocationEndpointClientAuthenticationMethod>()
                    .SetOrder(AttachRevocationEndpointClientAuthenticationMethod.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ProcessRevocationContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                ValidateClientAuthenticationMethod(context.RevocationEndpointClientAuthenticationMethod,
                    Metadata.RevocationEndpoint);

                return ValueTask.CompletedTask;
            }
        }

        private static void ValidateClientAuthenticationMethod(string? method, string endpoint)
        {
            if (string.IsNullOrEmpty(method) ||
                !OpenIddictClientFapi2Profile.ClientAuthenticationMethods.Contains(method, StringComparer.Ordinal))
            {
                throw new InvalidOperationException(SR.FormatID0984(endpoint));
            }
        }
    }
}
