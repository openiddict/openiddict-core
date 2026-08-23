/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers.Text;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } =
        [
            /*
             * Configuration request top-level processing:
             */
            ExtractConfigurationRequest.Descriptor,
            ValidateConfigurationRequest.Descriptor,
            HandleConfigurationRequest.Descriptor,
            ApplyConfigurationResponse<ProcessErrorContext>.Descriptor,
            ApplyConfigurationResponse<ProcessRequestContext>.Descriptor,

            /*
             * Configuration request handling:
             */
            AttachIssuer.Descriptor,
            AttachEndpoints.Descriptor,
            AttachGrantTypes.Descriptor,
            AttachResponseTypes.Descriptor,
            AttachResponseModes.Descriptor,
            AttachClientAuthenticationMethods.Descriptor,
            AttachCodeChallengeMethods.Descriptor,
            AttachScopes.Descriptor,
            AttachClaims.Descriptor,
            AttachSubjectTypes.Descriptor,
            AttachPromptValues.Descriptor,
            AttachSigningAlgorithms.Descriptor,
            AttachSecurityRequirements.Descriptor,
            AttachAdditionalMetadata.Descriptor,

            /*
             * JSON Web Key Set request top-level processing:
             */
            ExtractJsonWebKeySetRequest.Descriptor,
            ValidateJsonWebKeySetRequest.Descriptor,
            HandleJsonWebKeySetRequest.Descriptor,
            ApplyJsonWebKeySetResponse<ProcessErrorContext>.Descriptor,
            ApplyJsonWebKeySetResponse<ProcessRequestContext>.Descriptor,

            /*
             * JSON Web Key Set request handling:
             */
            AttachSigningKeys.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for extracting configuration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractConfigurationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseSingletonHandler<ExtractConfigurationRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ExtractConfigurationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0037));
                }

                context.Logger.LogInformation(6066, SR.GetResourceString(SR.ID6066), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating configuration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateConfigurationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseSingletonHandler<ValidateConfigurationRequest>()
                    .SetOrder(ExtractConfigurationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ValidateConfigurationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Logger.LogInformation(6067, SR.GetResourceString(SR.ID6067));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling configuration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleConfigurationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseSingletonHandler<HandleConfigurationRequest>()
                    .SetOrder(ValidateConfigurationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new HandleConfigurationRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                var response = new OpenIddictResponse
                {
                    [Metadata.Issuer] = notification.Issuer?.AbsoluteUri,
                    [Metadata.AuthorizationEndpoint] = notification.AuthorizationEndpoint?.AbsoluteUri,
                    [Metadata.TokenEndpoint] = notification.TokenEndpoint?.AbsoluteUri,
                    [Metadata.IntrospectionEndpoint] = notification.IntrospectionEndpoint?.AbsoluteUri,
                    [Metadata.EndSessionEndpoint] = notification.EndSessionEndpoint?.AbsoluteUri,
                    [Metadata.RevocationEndpoint] = notification.RevocationEndpoint?.AbsoluteUri,
                    [Metadata.UserInfoEndpoint] = notification.UserInfoEndpoint?.AbsoluteUri,
                    [Metadata.DeviceAuthorizationEndpoint] = notification.DeviceAuthorizationEndpoint?.AbsoluteUri,
                    [Metadata.PushedAuthorizationRequestEndpoint] = notification.PushedAuthorizationEndpoint?.AbsoluteUri,
                    [Metadata.MtlsEndpointAliases] = CreateMtlsEndpointAliases(notification),
                    [Metadata.JwksUri] = notification.JsonWebKeySetEndpoint?.AbsoluteUri,
                    [Metadata.GrantTypesSupported] = notification.GrantTypes.ToImmutableArray<string?>(),
                    [Metadata.ResponseTypesSupported] = notification.ResponseTypes.ToImmutableArray<string?>(),
                    [Metadata.ResponseModesSupported] = notification.ResponseModes.ToImmutableArray<string?>(),
                    [Metadata.ScopesSupported] = notification.Scopes.ToImmutableArray<string?>(),
                    [Metadata.ClaimsSupported] = notification.Claims.ToImmutableArray<string?>(),
                    [Metadata.IdTokenSigningAlgValuesSupported] = notification.IdTokenSigningAlgorithms.ToImmutableArray<string?>(),
                    [Metadata.CodeChallengeMethodsSupported] = notification.CodeChallengeMethods.ToImmutableArray<string?>(),
                    [Metadata.SubjectTypesSupported] = notification.SubjectTypes.ToImmutableArray<string?>(),
                    [Metadata.PromptValuesSupported] = notification.PromptValues.ToImmutableArray<string?>(),
                    [Metadata.TokenEndpointAuthMethodsSupported] = notification.TokenEndpointAuthenticationMethods.ToImmutableArray<string?>(),
                    [Metadata.IntrospectionEndpointAuthMethodsSupported] = notification.IntrospectionEndpointAuthenticationMethods.ToImmutableArray<string?>(),
                    [Metadata.RevocationEndpointAuthMethodsSupported] = notification.RevocationEndpointAuthenticationMethods.ToImmutableArray<string?>(),
                    [Metadata.DeviceAuthorizationEndpointAuthMethodsSupported] = notification.DeviceAuthorizationEndpointAuthenticationMethods.ToImmutableArray<string?>(),
                    [Metadata.PushedAuthorizationRequestEndpointAuthMethodsSupported] = notification.PushedAuthorizationEndpointAuthenticationMethods.ToImmutableArray<string?>(),
                    [Metadata.RequirePushedAuthorizationRequests] = notification.RequirePushedAuthorizationRequests,
                    [Metadata.TlsClientCertificateBoundAccessTokens] = notification.TlsClientCertificateBoundAccessTokens
                };

                foreach (var metadata in notification.Metadata)
                {
                    response.SetParameter(metadata.Key, metadata.Value);
                }

                context.Transaction.Response = response;

                static JsonObject CreateMtlsEndpointAliases(HandleConfigurationRequestContext context)
                {
                    var node = new JsonObject();

                    if (context.MtlsDeviceAuthorizationEndpointAlias is not null)
                    {
                        node.Add(Metadata.DeviceAuthorizationEndpoint, context.MtlsDeviceAuthorizationEndpointAlias.AbsoluteUri);
                    }

                    if (context.MtlsIntrospectionEndpointAlias is not null)
                    {
                        node.Add(Metadata.IntrospectionEndpoint, context.MtlsIntrospectionEndpointAlias.AbsoluteUri);
                    }

                    if (context.MtlsPushedAuthorizationEndpointAlias is not null)
                    {
                        node.Add(Metadata.PushedAuthorizationRequestEndpoint, context.MtlsPushedAuthorizationEndpointAlias.AbsoluteUri);
                    }

                    if (context.MtlsRevocationEndpointAlias is not null)
                    {
                        node.Add(Metadata.RevocationEndpoint, context.MtlsRevocationEndpointAlias.AbsoluteUri);
                    }

                    if (context.MtlsTokenEndpointAlias is not null)
                    {
                        node.Add(Metadata.TokenEndpoint, context.MtlsTokenEndpointAlias.AbsoluteUri);
                    }

                    if (context.MtlsUserInfoEndpointAlias is not null)
                    {
                        node.Add(Metadata.UserInfoEndpoint, context.MtlsUserInfoEndpointAlias.AbsoluteUri);
                    }

                    return node;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing configuration responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyConfigurationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyConfigurationResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseSingletonHandler<ApplyConfigurationResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ApplyConfigurationResponseContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0272));
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the issuer to the provider discovery document.
        /// </summary>
        public sealed class AttachIssuer : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachIssuer>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.Issuer = (context.Options.Issuer ?? context.BaseUri) switch
                {
                    { IsAbsoluteUri: true } uri => uri,

                    // Throw an exception if the issuer cannot be retrieved or is not valid.
                    _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0496))
                };

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the endpoint URIs to the provider discovery document.
        /// </summary>
        public sealed class AttachEndpoints : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachEndpoints>()
                    .SetOrder(AttachIssuer.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Note: while OpenIddict allows specifying multiple endpoint URIs, the OAuth 2.0
                // and OpenID Connect discovery specifications only allow a single URI per endpoint.

                context.AuthorizationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.AuthorizationEndpointUris.FirstOrDefault());

                context.DeviceAuthorizationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.DeviceAuthorizationEndpointUris.FirstOrDefault());

                context.EndSessionEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.EndSessionEndpointUris.FirstOrDefault());

                context.IntrospectionEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.IntrospectionEndpointUris.FirstOrDefault());

                context.JsonWebKeySetEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.JsonWebKeySetEndpointUris.FirstOrDefault());

                context.MtlsDeviceAuthorizationEndpointAlias ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.MtlsDeviceAuthorizationEndpointAliasUri);

                context.MtlsIntrospectionEndpointAlias ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.MtlsIntrospectionEndpointAliasUri);

                context.MtlsPushedAuthorizationEndpointAlias ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.MtlsPushedAuthorizationEndpointAliasUri);

                context.MtlsRevocationEndpointAlias ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.MtlsRevocationEndpointAliasUri);

                context.MtlsTokenEndpointAlias ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.MtlsTokenEndpointAliasUri);

                context.MtlsUserInfoEndpointAlias ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.MtlsUserInfoEndpointAliasUri);

                context.PushedAuthorizationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.PushedAuthorizationEndpointUris.FirstOrDefault());

                context.RevocationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.RevocationEndpointUris.FirstOrDefault());

                context.TokenEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.TokenEndpointUris.FirstOrDefault());

                context.UserInfoEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.UserInfoEndpointUris.FirstOrDefault());

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported grant types to the provider discovery document.
        /// </summary>
        public sealed class AttachGrantTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachGrantTypes>()
                    .SetOrder(AttachEndpoints.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.GrantTypes.UnionWith(context.Options.GrantTypes);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported response types to the provider discovery document.
        /// </summary>
        public sealed class AttachResponseTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachResponseTypes>()
                    .SetOrder(AttachGrantTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.ResponseTypes.UnionWith(context.Options.ResponseTypes);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported response modes to the provider discovery document.
        /// </summary>
        public sealed class AttachResponseModes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachResponseModes>()
                    .SetOrder(AttachResponseTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Only include the response modes if at least one response type is returned.
                if (context.ResponseTypes.Count is 0)
                {
                    return ValueTask.CompletedTask;
                }

                // Note: returning an access or identity token using the query response mode is explicitly disallowed.
                //
                // To ensure the query response mode is not returned unless at least one response type that doesn't
                // include id_token or token is included in the server configuration, a manual check is done here.
                if (context.Options.ResponseModes.Contains(ResponseModes.Query) &&
                    context.ResponseTypes
                        .Select(static types => types.Split(Separators.Space, StringSplitOptions.None).ToHashSet(StringComparer.Ordinal))
                        .Any(static types => !types.Contains(ResponseTypes.IdToken) && !types.Contains(ResponseTypes.Token)))
                {
                    context.ResponseModes.Add(ResponseModes.Query);
                }

                context.ResponseModes.UnionWith(context.Options.ResponseModes.Where(
                    static mode => mode is not ResponseModes.Query));

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported client
        /// authentication methods to the provider discovery document.
        /// </summary>
        public sealed class AttachClientAuthenticationMethods : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachClientAuthenticationMethods>()
                    .SetOrder(AttachResponseModes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Note: "device_authorization_endpoint_auth_methods_supported" is not a standard parameter
                // but is supported by OpenIddict 4.3.0 and higher for consistency with the other endpoints.
                if (context.DeviceAuthorizationEndpoint is not null)
                {
                    context.DeviceAuthorizationEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                if (context.IntrospectionEndpoint is not null)
                {
                    context.IntrospectionEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                // Note: "pushed_authorization_request_endpoint_auth_methods_supported" is not a standard parameter
                // but is supported by OpenIddict 6.1.0 and higher for consistency with the other endpoints.
                if (context.PushedAuthorizationEndpoint is not null)
                {
                    context.PushedAuthorizationEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                if (context.RevocationEndpoint is not null)
                {
                    context.RevocationEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                if (context.TokenEndpoint is not null)
                {
                    context.TokenEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported
        /// code challenge methods to the provider discovery document.
        /// </summary>
        public sealed class AttachCodeChallengeMethods : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachCodeChallengeMethods>()
                    .SetOrder(AttachClientAuthenticationMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Only include the code challenge methods if the authorization code grant type is enabled.
                if (context.GrantTypes.Contains(GrantTypes.AuthorizationCode))
                {
                    context.CodeChallengeMethods.UnionWith(context.Options.CodeChallengeMethods);
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported response types to the provider discovery document.
        /// </summary>
        public sealed class AttachScopes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachScopes>()
                    .SetOrder(AttachCodeChallengeMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.Scopes.UnionWith(context.Options.Scopes);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported claims to the provider discovery document.
        /// </summary>
        public sealed class AttachClaims : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachClaims>()
                    .SetOrder(AttachScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.Claims.UnionWith(context.Options.Claims);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported subject types to the provider discovery document.
        /// </summary>
        public sealed class AttachSubjectTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachSubjectTypes>()
                    .SetOrder(AttachClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.SubjectTypes.UnionWith(context.Options.SubjectTypes);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported prompt values to the provider discovery document.
        /// </summary>
        public sealed class AttachPromptValues : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachPromptValues>()
                    .SetOrder(AttachSubjectTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.PromptValues.UnionWith(context.Options.PromptValues);

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported signing algorithms to the provider discovery document.
        /// </summary>
        public sealed class AttachSigningAlgorithms : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachSigningAlgorithms>()
                    .SetOrder(AttachPromptValues.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                foreach (var credentials in context.Options.SigningCredentials)
                {
                    // Try to resolve the JWA algorithm short name.
                    var algorithm = credentials.Algorithm switch
                    {
                        SecurityAlgorithms.EcdsaSha256 or SecurityAlgorithms.EcdsaSha256Signature
                            => SecurityAlgorithms.EcdsaSha256,
                        SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.EcdsaSha384Signature
                            => SecurityAlgorithms.EcdsaSha384,
                        SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.EcdsaSha512Signature
                            => SecurityAlgorithms.EcdsaSha512,

                        SecurityAlgorithms.MlDsa44 => SecurityAlgorithms.MlDsa44,
                        SecurityAlgorithms.MlDsa65 => SecurityAlgorithms.MlDsa65,
                        SecurityAlgorithms.MlDsa87 => SecurityAlgorithms.MlDsa87,

                        SecurityAlgorithms.RsaSha256 or SecurityAlgorithms.RsaSha256Signature
                            => SecurityAlgorithms.RsaSha256,
                        SecurityAlgorithms.RsaSha384 or SecurityAlgorithms.RsaSha384Signature
                            => SecurityAlgorithms.RsaSha384,
                        SecurityAlgorithms.RsaSha512 or SecurityAlgorithms.RsaSha512Signature
                            => SecurityAlgorithms.RsaSha512,

                        SecurityAlgorithms.RsaSsaPssSha256 or SecurityAlgorithms.RsaSsaPssSha256Signature
                            => SecurityAlgorithms.RsaSsaPssSha256,
                        SecurityAlgorithms.RsaSsaPssSha384 or SecurityAlgorithms.RsaSsaPssSha384Signature
                            => SecurityAlgorithms.RsaSsaPssSha384,
                        SecurityAlgorithms.RsaSsaPssSha512 or SecurityAlgorithms.RsaSsaPssSha512Signature
                            => SecurityAlgorithms.RsaSsaPssSha512,

                        _ => null
                    };

                    // If the algorithm cannot be resolved, ignore it.
                    if (string.IsNullOrEmpty(algorithm))
                    {
                        continue;
                    }

                    context.IdTokenSigningAlgorithms.Add(algorithm);
                }

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the security requirements to the provider discovery document.
        /// </summary>
        public sealed class AttachSecurityRequirements : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachSecurityRequirements>()
                    .SetOrder(AttachSigningAlgorithms.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                context.RequirePushedAuthorizationRequests = context.Options.RequirePushedAuthorizationRequests;
                context.TlsClientCertificateBoundAccessTokens = context.Options.UseClientCertificateBoundAccessTokens;

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching additional metadata to the provider discovery document.
        /// </summary>
        public sealed class AttachAdditionalMetadata : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachAdditionalMetadata>()
                    .SetOrder(AttachSecurityRequirements.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                // Note: these optional features are not yet supported by OpenIddict,
                // so "false" is returned to encourage clients not to use them.
                context.Metadata[Metadata.ClaimsParameterSupported] = false;
                context.Metadata[Metadata.RequestParameterSupported] = false;
                context.Metadata[Metadata.RequestUriParameterSupported] = false;

                // As of 3.2.0, OpenIddict automatically returns an "iss" parameter containing its identity as
                // part of authorization responses to help clients mitigate mix-up attacks. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-iss-auth-resp-05.
                context.Metadata[Metadata.AuthorizationResponseIssParameterSupported] = true;

                return ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting JSON Web Key Set requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractJsonWebKeySetRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractJsonWebKeySetRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseSingletonHandler<ExtractJsonWebKeySetRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ExtractJsonWebKeySetRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0038));
                }

                context.Logger.LogInformation(6068, SR.GetResourceString(SR.ID6068), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating JSON Web Key Set requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateJsonWebKeySetRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateJsonWebKeySetRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseSingletonHandler<ValidateJsonWebKeySetRequest>()
                    .SetOrder(ExtractJsonWebKeySetRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ValidateJsonWebKeySetRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                context.Logger.LogInformation(6069, SR.GetResourceString(SR.ID6069));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling JSON Web Key Set requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleJsonWebKeySetRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleJsonWebKeySetRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseSingletonHandler<HandleJsonWebKeySetRequest>()
                    .SetOrder(ValidateJsonWebKeySetRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new HandleJsonWebKeySetRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                if (notification.IsRejected)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                List<JsonObject> keys = [];

                for (var index = 0; index < notification.Keys.Count; index++)
                {
                    // Ensure a key type has been provided.
                    // See https://tools.ietf.org/html/rfc7517#section-4.1
                    if (string.IsNullOrEmpty(notification.Keys[index].Kty))
                    {
                        context.Logger.LogWarning(6070, SR.GetResourceString(SR.ID6070), JsonWebKeyParameterNames.Kty);

                        continue;
                    }

                    // Important: the JSON Web Keys returned to the caller MUST NOT
                    // include ANY parameter containing private key material.

                    var key = new JsonObject();

                    if (!string.IsNullOrEmpty(notification.Keys[index].Kid))
                    {
                        key[JsonWebKeyParameterNames.Kid] = notification.Keys[index].Kid;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].Use))
                    {
                        key[JsonWebKeyParameterNames.Use] = notification.Keys[index].Use;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].Kty))
                    {
                        key[JsonWebKeyParameterNames.Kty] = notification.Keys[index].Kty;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].Alg))
                    {
                        key[JsonWebKeyParameterNames.Alg] = notification.Keys[index].Alg;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].Crv))
                    {
                        key[JsonWebKeyParameterNames.Crv] = notification.Keys[index].Crv;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].E))
                    {
                        key[JsonWebKeyParameterNames.E] = notification.Keys[index].E;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].N))
                    {
                        key[JsonWebKeyParameterNames.N] = notification.Keys[index].N;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].X))
                    {
                        key[JsonWebKeyParameterNames.X] = notification.Keys[index].X;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].Y))
                    {
                        key[JsonWebKeyParameterNames.Y] = notification.Keys[index].Y;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].Pub))
                    {
                        key[JsonWebKeyParameterNames.Pub] = notification.Keys[index].Pub;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].X5t))
                    {
                        key[JsonWebKeyParameterNames.X5t] = notification.Keys[index].X5t;
                    }

                    if (!string.IsNullOrEmpty(notification.Keys[index].X5u))
                    {
                        key[JsonWebKeyParameterNames.X5u] = notification.Keys[index].X5u;
                    }

                    if (notification.Keys[index].KeyOps.Count is not 0)
                    {
                        key[JsonWebKeyParameterNames.KeyOps] = new JsonArray([.. notification.Keys[index].KeyOps]);
                    }

                    if (notification.Keys[index].X5c.Count is not 0)
                    {
                        key[JsonWebKeyParameterNames.X5c] = new JsonArray([.. notification.Keys[index].X5c]);
                    }

                    keys.Add(key);
                }

                // Note: AddParameter() is used here to ensure the mandatory "keys" node
                // is returned to the caller, even if the key set doesn't expose any key.
                // See https://tools.ietf.org/html/rfc7517#section-5 for more information.
                var response = new OpenIddictResponse();
                response.AddParameter(Parameters.Keys, new JsonArray([.. keys]));

                context.Transaction.Response = response;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing JSON Web Key Set responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyJsonWebKeySetResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyJsonWebKeySetResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseSingletonHandler<ApplyJsonWebKeySetResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                var notification = new ApplyJsonWebKeySetResponseContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled)
                {
                    context.HandleRequest();
                    return;
                }

                if (notification.IsRequestSkipped)
                {
                    context.SkipRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0039));
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the signing keys to the JSON Web Key Set document.
        /// </summary>
        public sealed class AttachSigningKeys : IOpenIddictServerHandler<HandleJsonWebKeySetRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleJsonWebKeySetRequestContext>()
                    .UseSingletonHandler<AttachSigningKeys>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleJsonWebKeySetRequestContext context)
            {
                ArgumentNullException.ThrowIfNull(context);

                foreach (var credentials in context.Options.SigningCredentials)
                {
                    if (!credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa44)     &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa65)     &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa87)     &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256)   &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSsaPssSha256))
                    {
                        context.Logger.LogInformation(6071, SR.GetResourceString(SR.ID6071), credentials.Key.GetType().Name);

                        continue;
                    }

                    // Important: the JSON Web Keys returned to the caller MUST NOT
                    // include ANY parameter containing private key material.

                    var key = new JsonWebKey
                    {
                        Use = JsonWebKeyUseNames.Sig,

                        // Resolve the JWA identifier from the algorithm specified in the credentials.
                        Alg = credentials.Algorithm switch
                        {
                            SecurityAlgorithms.EcdsaSha256 or SecurityAlgorithms.EcdsaSha256Signature
                                => SecurityAlgorithms.EcdsaSha256,
                            SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.EcdsaSha384Signature
                                => SecurityAlgorithms.EcdsaSha384,
                            SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.EcdsaSha512Signature
                                => SecurityAlgorithms.EcdsaSha512,

                            SecurityAlgorithms.RsaSha256 or SecurityAlgorithms.RsaSha256Signature
                                => SecurityAlgorithms.RsaSha256,
                            SecurityAlgorithms.RsaSha384 or SecurityAlgorithms.RsaSha384Signature
                                => SecurityAlgorithms.RsaSha384,
                            SecurityAlgorithms.RsaSha512 or SecurityAlgorithms.RsaSha512Signature
                                => SecurityAlgorithms.RsaSha512,

                            SecurityAlgorithms.RsaSsaPssSha256 or SecurityAlgorithms.RsaSsaPssSha256Signature
                                => SecurityAlgorithms.RsaSsaPssSha256,
                            SecurityAlgorithms.RsaSsaPssSha384 or SecurityAlgorithms.RsaSsaPssSha384Signature
                                => SecurityAlgorithms.RsaSsaPssSha384,
                            SecurityAlgorithms.RsaSsaPssSha512 or SecurityAlgorithms.RsaSsaPssSha512Signature
                                => SecurityAlgorithms.RsaSsaPssSha512,

                            SecurityAlgorithms.MlDsa44 => SecurityAlgorithms.MlDsa44,
                            SecurityAlgorithms.MlDsa65 => SecurityAlgorithms.MlDsa65,
                            SecurityAlgorithms.MlDsa87 => SecurityAlgorithms.MlDsa87,

                            _ => null
                        },

                        // Use the key identifier specified in the signing credentials.
                        Kid = credentials.Kid
                    };

                    if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
                        credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
                        credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                    {
                        if (!TryGetECParameters(credentials.Key, out var parameters))
                        {
                            context.Logger.LogWarning(6074, SR.GetResourceString(SR.ID6074), credentials.Key.GetType().Name);

                            continue;
                        }

                        // Warning: on .NET Framework 4.x, exported ECParameters generally have a null OID
                        // value attached. To work around this limitation, both the raw OID values and the
                        // friendly names are compared to determine whether the curve is of the specified type.
                        var curve = parameters.Curve.Oid switch
                        {
                            { FriendlyName: "nistP256" } or { Value: "1.2.840.10045.3.1.7" } => JsonWebKeyECTypes.P256,
                            { FriendlyName: "nistP384" } or { Value: "1.3.132.0.34"        } => JsonWebKeyECTypes.P384,
                            { FriendlyName: "nistP521" } or { Value: "1.3.132.0.35"        } => JsonWebKeyECTypes.P521,

                            _ => null
                        };

                        if (string.IsNullOrEmpty(curve))
                        {
                            context.Logger.LogWarning(6167, SR.GetResourceString(SR.ID6167), credentials.Key.GetType().Name);

                            continue;
                        }

                        Debug.Assert(parameters.Q.X is not null && parameters.Q.Y is not null, SR.GetResourceString(SR.ID4004));

                        key.Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;
                        key.Crv = curve;

                        // Note: both X and Y must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7518#section-6.2.1.2.
                        key.X = Base64Url.EncodeToString(parameters.Q.X);
                        key.Y = Base64Url.EncodeToString(parameters.Q.Y);
                    }

                    // Note: while ML-DSA is supported on .NET Framework via the Microsoft.Bcl.Cryptography package, SHAKE256 - used
                    // to produce and validate access token and authorization code hashes when a ML-DSA key is used - is not supported.
                    //
                    // As a result, ML-DSA keys are not supported by OpenIddict on .NET Framework and are ignored here.
                    else if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa44) ||
                             credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa65) ||
                             credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.MlDsa87))
                    {
                        if (!TryGetMLDsaPublicKey(credentials.Key, out byte[]? blob))
                        {
                            context.Logger.LogWarning(6297, SR.GetResourceString(SR.ID6296), credentials.Key.GetType().Name);

                            continue;
                        }

                        key.Kty = JsonWebAlgorithmsKeyTypes.Akp;
                        key.Pub = Base64Url.EncodeToString(blob);
                    }

                    else if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256) ||
                             credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSsaPssSha256))
                    {
                        if (!TryGetRSAParameters(credentials.Key, out RSAParameters parameters))
                        {
                            context.Logger.LogWarning(6073, SR.GetResourceString(SR.ID6073), credentials.Key.GetType().Name);

                            continue;
                        }

                        Debug.Assert(parameters.Exponent is not null && parameters.Modulus is not null, SR.GetResourceString(SR.ID4003));

                        key.Kty = JsonWebAlgorithmsKeyTypes.RSA;

                        // Note: both E and N must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7518#section-6.3.1.1.
                        key.E = Base64Url.EncodeToString(parameters.Exponent);
                        key.N = Base64Url.EncodeToString(parameters.Modulus);
                    }

                    // If the signing key is embedded in a X.509 certificate, set
                    // the x5t and x5c parameters using the certificate details.
                    if (credentials.Key is X509SecurityKey { Certificate: X509Certificate2 certificate })
                    {
                        // x5t must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7517#section-4.8.
                        key.X5t = Base64Url.EncodeToString(certificate.GetCertHash());

                        // x5t#S256 must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7517#section-4.9.
                        key.X5tS256 = Base64Url.EncodeToString(certificate.GetCertHash(HashAlgorithmName.SHA256));

                        // Unlike E or N, the certificates contained in x5c
                        // must be base64-encoded and not base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7517#section-4.7.
                        key.X5c.Add(Convert.ToBase64String(certificate.RawData));
                    }

                    context.Keys.Add(key);
                }

                return ValueTask.CompletedTask;

                // Note: IdentityModel 5+ doesn't expose a method allowing to retrieve the underlying algorithm
                // from a generic security key. To work around this limitation, these local functions try to
                // cast the security key to the built-in IdentityModel types to extract the required instance.
                //
                // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/395.

                static bool TryGetECParameters(SecurityKey key, out ECParameters parameters)
                {
                    switch (key)
                    {
                        case X509SecurityKey { PublicKey: ECDsa algorithm }:
                            parameters = algorithm.ExportParameters(includePrivateParameters: false);
                            return true;

                        case ECDsaSecurityKey { ECDsa: ECDsa algorithm }:
                            parameters = algorithm.ExportParameters(includePrivateParameters: false);
                            return true;

                        default:
                            parameters = default;
                            return false;
                    }
                }

                static bool TryGetMLDsaPublicKey(SecurityKey key, [NotNullWhen(true)] out byte[]? blob)
                {
                    switch (key)
                    {
                        case X509SecurityKey { Certificate: X509Certificate2 certificate }
#pragma warning disable SYSLIB5006
                            when certificate.GetMLDsaPublicKey() is MLDsa algorithm:
#pragma warning restore SYSLIB5006
                            blob = algorithm.ExportMLDsaPublicKey();
                            return true;

                        case MlDsaSecurityKey { MLDsa: MLDsa algorithm }:
                            blob = algorithm.ExportMLDsaPublicKey();
                            return true;

                        default:
                            blob = default;
                            return false;
                    }
                }

                static bool TryGetRSAParameters(SecurityKey key, out RSAParameters parameters)
                {
                    switch (key)
                    {
                        case X509SecurityKey { PublicKey: RSA algorithm }:
                            parameters = algorithm.ExportParameters(includePrivateParameters: false);
                            return true;

                        case RsaSecurityKey { Rsa: RSA algorithm }:
                            parameters = algorithm.ExportParameters(includePrivateParameters: false);
                            return true;

                        case RsaSecurityKey { Parameters: RSAParameters value }:
                            parameters = value;
                            return true;

                        default:
                            parameters = default;
                            return false;
                    }
                }
            }
        }
    }
}
