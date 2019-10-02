/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    public static partial class OpenIddictServerHandlers
    {
        public static class Discovery
        {
            public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
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
                AttachEndpoints.Descriptor,
                AttachGrantTypes.Descriptor,
                AttachResponseModes.Descriptor,
                AttachResponseTypes.Descriptor,
                AttachClientAuthenticationMethods.Descriptor,
                AttachCodeChallengeMethods.Descriptor,
                AttachScopes.Descriptor,
                AttachClaims.Descriptor,
                AttachSubjectTypes.Descriptor,
                AttachSigningAlgorithms.Descriptor,
                AttachAdditionalMetadata.Descriptor,

                /*
                 * Cryptography request top-level processing:
                 */
                ExtractCryptographyRequest.Descriptor,
                ValidateCryptographyRequest.Descriptor,
                HandleCryptographyRequest.Descriptor,
                ApplyCryptographyResponse<ProcessErrorContext>.Descriptor,
                ApplyCryptographyResponse<ProcessRequestContext>.Descriptor,

                /*
                 * Cryptography request handling:
                 */
                AttachSigningKeys.Descriptor);

            /// <summary>
            /// Contains the logic responsible of extracting configuration requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ExtractConfigurationRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ExtractConfigurationRequest>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Configuration)
                    {
                        return;
                    }

                    var notification = new ExtractConfigurationRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    if (notification.Request == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The configuration request was not correctly extracted. To extract configuration requests, ")
                            .Append("create a class implementing 'IOpenIddictServerHandler<ExtractConfigurationRequestContext>' ")
                            .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    context.Logger.LogInformation("The configuration request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating configuration requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateConfigurationRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ValidateConfigurationRequest>()
                        .SetOrder(ExtractConfigurationRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Configuration)
                    {
                        return;
                    }

                    var notification = new ValidateConfigurationRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    context.Logger.LogInformation("The configuration request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling configuration requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public HandleConfigurationRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<HandleConfigurationRequest>()
                        .SetOrder(ValidateConfigurationRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Configuration)
                    {
                        return;
                    }

                    var notification = new HandleConfigurationRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    var response = new OpenIddictResponse
                    {
                        [Metadata.Issuer] = notification.Issuer?.AbsoluteUri,
                        [Metadata.AuthorizationEndpoint] = notification.AuthorizationEndpoint?.AbsoluteUri,
                        [Metadata.TokenEndpoint] = notification.TokenEndpoint?.AbsoluteUri,
                        [Metadata.IntrospectionEndpoint] = notification.IntrospectionEndpoint?.AbsoluteUri,
                        [Metadata.EndSessionEndpoint] = notification.LogoutEndpoint?.AbsoluteUri,
                        [Metadata.RevocationEndpoint] = notification.RevocationEndpoint?.AbsoluteUri,
                        [Metadata.UserinfoEndpoint] = notification.UserinfoEndpoint?.AbsoluteUri,
                        [Metadata.JwksUri] = notification.CryptographyEndpoint?.AbsoluteUri,
                        [Metadata.GrantTypesSupported] = notification.GrantTypes.ToArray(),
                        [Metadata.ResponseTypesSupported] = notification.ResponseTypes.ToArray(),
                        [Metadata.ResponseModesSupported] = notification.ResponseModes.ToArray(),
                        [Metadata.ScopesSupported] = notification.Scopes.ToArray(),
                        [Metadata.ClaimsSupported] = notification.Claims.ToArray(),
                        [Metadata.IdTokenSigningAlgValuesSupported] = notification.IdTokenSigningAlgorithms.ToArray(),
                        [Metadata.CodeChallengeMethodsSupported] = notification.CodeChallengeMethods.ToArray(),
                        [Metadata.SubjectTypesSupported] = notification.SubjectTypes.ToArray(),
                        [Metadata.TokenEndpointAuthMethodsSupported] = notification.TokenEndpointAuthenticationMethods.ToArray(),
                        [Metadata.IntrospectionEndpointAuthMethodsSupported] = notification.IntrospectionEndpointAuthenticationMethods.ToArray(),
                        [Metadata.RevocationEndpointAuthMethodsSupported] = notification.RevocationEndpointAuthenticationMethods.ToArray()
                    };

                    foreach (var metadata in notification.Metadata)
                    {
                        response.SetParameter(metadata.Key, metadata.Value);
                    }

                    context.Response = response;
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing configuration responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyConfigurationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerProvider _provider;

                public ApplyConfigurationResponse([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseScopedHandler<ApplyConfigurationResponse<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Configuration)
                    {
                        return;
                    }

                    var notification = new ApplyConfigurationResponseContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The configuration response was not correctly applied. To apply configuration response, ")
                        .Append("create a class implementing 'IOpenIddictServerHandler<ApplyConfigurationResponseContext>' ")
                        .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .ToString());
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the endpoint URLs to the provider discovery document.
            /// </summary>
            public class AttachEndpoints : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachEndpoints>()
                        .SetOrder(int.MaxValue - 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: while OpenIddict allows specifying multiple endpoint addresses, the OAuth 2.0
                    // and OpenID Connect discovery specifications only allow a single address per endpoint.
                    context.AuthorizationEndpoint ??= context.Options.AuthorizationEndpointUris.FirstOrDefault();
                    context.CryptographyEndpoint  ??= context.Options.CryptographyEndpointUris.FirstOrDefault();
                    context.IntrospectionEndpoint ??= context.Options.IntrospectionEndpointUris.FirstOrDefault();
                    context.LogoutEndpoint        ??= context.Options.LogoutEndpointUris.FirstOrDefault();
                    context.RevocationEndpoint    ??= context.Options.RevocationEndpointUris.FirstOrDefault();
                    context.TokenEndpoint         ??= context.Options.TokenEndpointUris.FirstOrDefault();
                    context.UserinfoEndpoint      ??= context.Options.UserinfoEndpointUris.FirstOrDefault();

                    // Note: this handler doesn't have any access to the request context. As such, it depends
                    // on another handler to determine the issuer location from the ambient request if it was not
                    // explicitly set in the server options. If the issuer is not set, an exception is thrown.
                    if (context.AuthorizationEndpoint != null && !context.AuthorizationEndpoint.IsAbsoluteUri)
                    {
                        if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("An absolute URL cannot be built for the authorization endpoint path.");
                        }

                        context.AuthorizationEndpoint = new Uri(context.Issuer, context.AuthorizationEndpoint);
                    }

                    if (context.CryptographyEndpoint != null && !context.CryptographyEndpoint.IsAbsoluteUri)
                    {
                        if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("An absolute URL cannot be built for the cryptography endpoint path.");
                        }

                        context.CryptographyEndpoint = new Uri(context.Issuer, context.CryptographyEndpoint);
                    }

                    if (context.IntrospectionEndpoint != null && !context.IntrospectionEndpoint.IsAbsoluteUri)
                    {
                        if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("An absolute URL cannot be built for the introspection endpoint path.");
                        }

                        context.IntrospectionEndpoint = new Uri(context.Issuer, context.IntrospectionEndpoint);
                    }

                    if (context.LogoutEndpoint != null && !context.LogoutEndpoint.IsAbsoluteUri)
                    {
                        if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("An absolute URL cannot be built for the logout endpoint path.");
                        }

                        context.LogoutEndpoint = new Uri(context.Issuer, context.LogoutEndpoint);
                    }

                    if (context.RevocationEndpoint != null && !context.RevocationEndpoint.IsAbsoluteUri)
                    {
                        if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("An absolute URL cannot be built for the revocation endpoint path.");
                        }

                        context.RevocationEndpoint = new Uri(context.Issuer, context.RevocationEndpoint);
                    }

                    if (context.TokenEndpoint != null && !context.TokenEndpoint.IsAbsoluteUri)
                    {
                        if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("An absolute URL cannot be built for the token endpoint path.");
                        }

                        context.TokenEndpoint = new Uri(context.Issuer, context.TokenEndpoint);
                    }

                    if (context.UserinfoEndpoint != null && !context.UserinfoEndpoint.IsAbsoluteUri)
                    {
                        if (context.Issuer == null || !context.Issuer.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("An absolute URL cannot be built for the userinfo endpoint path.");
                        }

                        context.UserinfoEndpoint = new Uri(context.Issuer, context.UserinfoEndpoint);
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported grant types to the provider discovery document.
            /// </summary>
            public class AttachGrantTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachGrantTypes>()
                        .SetOrder(AttachEndpoints.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.GrantTypes.UnionWith(context.Options.GrantTypes);

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported response modes to the provider discovery document.
            /// </summary>
            public class AttachResponseModes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachResponseModes>()
                        .SetOrder(AttachGrantTypes.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.ResponseModes.UnionWith(context.Options.ResponseModes);

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported response types to the provider discovery document.
            /// </summary>
            public class AttachResponseTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachResponseTypes>()
                        .SetOrder(AttachResponseModes.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.ResponseTypes.UnionWith(context.Options.ResponseTypes);

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported client
            /// authentication methods to the provider discovery document.
            /// </summary>
            public class AttachClientAuthenticationMethods : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachClientAuthenticationMethods>()
                        .SetOrder(AttachResponseTypes.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.IntrospectionEndpoint != null)
                    {
                        context.IntrospectionEndpointAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretBasic);
                        context.IntrospectionEndpointAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretPost);
                    }

                    if (context.RevocationEndpoint != null)
                    {
                        context.RevocationEndpointAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretBasic);
                        context.RevocationEndpointAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretPost);
                    }

                    if (context.TokenEndpoint != null)
                    {
                        context.TokenEndpointAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretBasic);
                        context.TokenEndpointAuthenticationMethods.Add(ClientAuthenticationMethods.ClientSecretPost);
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported
            /// code challenge methods to the provider discovery document.
            /// </summary>
            public class AttachCodeChallengeMethods : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachCodeChallengeMethods>()
                        .SetOrder(AttachClientAuthenticationMethods.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Only populate code_challenge_methods_supported if the code flow was enabled.
                    if (context.GrantTypes.Contains(GrantTypes.AuthorizationCode))
                    {
                        // Note: supporting S256 is mandatory for authorization servers that implement PKCE.
                        // See https://tools.ietf.org/html/rfc7636#section-4.2 for more information.
                        context.CodeChallengeMethods.Add(CodeChallengeMethods.Plain);
                        context.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported response types to the provider discovery document.
            /// </summary>
            public class AttachScopes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachScopes>()
                        .SetOrder(AttachCodeChallengeMethods.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.Scopes.UnionWith(context.Options.Scopes);

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported claims to the provider discovery document.
            /// </summary>
            public class AttachClaims : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachClaims>()
                        .SetOrder(AttachScopes.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.Claims.UnionWith(context.Options.Claims);

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported subject types to the provider discovery document.
            /// </summary>
            public class AttachSubjectTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachSubjectTypes>()
                        .SetOrder(AttachClaims.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    context.SubjectTypes.Add(SubjectTypes.Public);

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the supported signing algorithms to the provider discovery document.
            /// </summary>
            public class AttachSigningAlgorithms : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachSigningAlgorithms>()
                        .SetOrder(AttachSubjectTypes.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    foreach (var credentials in context.Options.SigningCredentials)
                    {
                        // Try to resolve the JWA algorithm short name.
                        var algorithm = credentials.Algorithm switch
                        {
#if SUPPORTS_ECDSA
                            SecurityAlgorithms.EcdsaSha256 => SecurityAlgorithms.EcdsaSha256,
                            SecurityAlgorithms.EcdsaSha384 => SecurityAlgorithms.EcdsaSha384,
                            SecurityAlgorithms.EcdsaSha512 => SecurityAlgorithms.EcdsaSha512,
                            SecurityAlgorithms.EcdsaSha256Signature => SecurityAlgorithms.EcdsaSha256,
                            SecurityAlgorithms.EcdsaSha384Signature => SecurityAlgorithms.EcdsaSha384,
                            SecurityAlgorithms.EcdsaSha512Signature => SecurityAlgorithms.EcdsaSha512,
#endif
                            SecurityAlgorithms.RsaSha256 => SecurityAlgorithms.RsaSha256,
                            SecurityAlgorithms.RsaSha384 => SecurityAlgorithms.RsaSha384,
                            SecurityAlgorithms.RsaSha512 => SecurityAlgorithms.RsaSha512,
                            SecurityAlgorithms.RsaSha256Signature => SecurityAlgorithms.RsaSha256,
                            SecurityAlgorithms.RsaSha384Signature => SecurityAlgorithms.RsaSha384,
                            SecurityAlgorithms.RsaSha512Signature => SecurityAlgorithms.RsaSha512,

                            SecurityAlgorithms.RsaSsaPssSha256 => SecurityAlgorithms.RsaSsaPssSha256,
                            SecurityAlgorithms.RsaSsaPssSha384 => SecurityAlgorithms.RsaSsaPssSha384,
                            SecurityAlgorithms.RsaSsaPssSha512 => SecurityAlgorithms.RsaSsaPssSha512,
                            SecurityAlgorithms.RsaSsaPssSha256Signature => SecurityAlgorithms.RsaSsaPssSha256,
                            SecurityAlgorithms.RsaSsaPssSha384Signature => SecurityAlgorithms.RsaSsaPssSha384,
                            SecurityAlgorithms.RsaSsaPssSha512Signature => SecurityAlgorithms.RsaSsaPssSha512,

                            _ => null
                        };

                        // If the algorithm cannot be resolved, ignore it.
                        if (string.IsNullOrEmpty(algorithm))
                        {
                            continue;
                        }

                        context.IdTokenSigningAlgorithms.Add(algorithm);
                    }

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching additional metadata to the provider discovery document.
            /// </summary>
            public class AttachAdditionalMetadata : IOpenIddictServerHandler<HandleConfigurationRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                        .UseSingletonHandler<AttachAdditionalMetadata>()
                        .SetOrder(AttachSigningAlgorithms.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleConfigurationRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    // Note: the optional claims/request/request_uri parameters are not yet supported
                    // by OpenIddict, so "false" is returned to encourage clients not to use them.
                    context.Metadata[Metadata.ClaimsParameterSupported] = false;
                    context.Metadata[Metadata.RequestParameterSupported] = false;
                    context.Metadata[Metadata.RequestUriParameterSupported] = false;

                    return default;
                }
            }

            /// <summary>
            /// Contains the logic responsible of extracting cryptography requests and invoking the corresponding event handlers.
            /// </summary>
            public class ExtractCryptographyRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ExtractCryptographyRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ExtractCryptographyRequest>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Cryptography)
                    {
                        return;
                    }

                    var notification = new ExtractCryptographyRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    if (notification.Request == null)
                    {
                        throw new InvalidOperationException(new StringBuilder()
                            .Append("The cryptography request was not correctly extracted. To extract configuration requests, ")
                            .Append("create a class implementing 'IOpenIddictServerHandler<ExtractCryptographyRequestContext>' ")
                            .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                            .ToString());
                    }

                    context.Logger.LogInformation("The cryptography request was successfully extracted: {Request}.", notification.Request);
                }
            }

            /// <summary>
            /// Contains the logic responsible of validating cryptography requests and invoking the corresponding event handlers.
            /// </summary>
            public class ValidateCryptographyRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public ValidateCryptographyRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<ValidateCryptographyRequest>()
                        .SetOrder(ExtractCryptographyRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Cryptography)
                    {
                        return;
                    }

                    var notification = new ValidateCryptographyRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    context.Logger.LogInformation("The cryptography request was successfully validated.");
                }
            }

            /// <summary>
            /// Contains the logic responsible of handling cryptography requests and invoking the corresponding event handlers.
            /// </summary>
            public class HandleCryptographyRequest : IOpenIddictServerHandler<ProcessRequestContext>
            {
                private readonly IOpenIddictServerProvider _provider;

                public HandleCryptographyRequest([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                        .UseScopedHandler<HandleCryptographyRequest>()
                        .SetOrder(ValidateCryptographyRequest.Descriptor.Order + 1_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] ProcessRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Cryptography)
                    {
                        return;
                    }

                    var notification = new HandleCryptographyRequestContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    var keys = new JArray();

                    foreach (var key in notification.Keys)
                    {
                        var item = new JObject();

                        // Ensure a key type has been provided.
                        // See https://tools.ietf.org/html/rfc7517#section-4.1
                        if (string.IsNullOrEmpty(key.Kty))
                        {
                            context.Logger.LogError("A JSON Web Key was excluded from the key set because " +
                                                    "it didn't contain the mandatory 'kid' parameter.");

                            continue;
                        }

                        // Create a dictionary associating the
                        // JsonWebKey components with their values.
                        var parameters = new Dictionary<string, string>
                        {
                            [JsonWebKeyParameterNames.Kid] = key.Kid,
                            [JsonWebKeyParameterNames.Use] = key.Use,
                            [JsonWebKeyParameterNames.Kty] = key.Kty,
                            [JsonWebKeyParameterNames.Alg] = key.Alg,
                            [JsonWebKeyParameterNames.Crv] = key.Crv,
                            [JsonWebKeyParameterNames.E] = key.E,
                            [JsonWebKeyParameterNames.N] = key.N,
                            [JsonWebKeyParameterNames.X] = key.X,
                            [JsonWebKeyParameterNames.Y] = key.Y,
                            [JsonWebKeyParameterNames.X5t] = key.X5t,
                            [JsonWebKeyParameterNames.X5u] = key.X5u
                        };

                        foreach (var parameter in parameters)
                        {
                            if (!string.IsNullOrEmpty(parameter.Value))
                            {
                                item.Add(parameter.Key, parameter.Value);
                            }
                        }

                        if (key.KeyOps.Count != 0)
                        {
                            item.Add(JsonWebKeyParameterNames.KeyOps, new JArray(key.KeyOps));
                        }

                        if (key.X5c.Count != 0)
                        {
                            item.Add(JsonWebKeyParameterNames.X5c, new JArray(key.X5c));
                        }

                        keys.Add(item);
                    }

                    // Note: AddParameter() is used here to ensure the mandatory "keys" node
                    // is returned to the caller, even if the key set doesn't expose any key.
                    // See https://tools.ietf.org/html/rfc7517#section-5 for more information.
                    var response = new OpenIddictResponse();
                    response.AddParameter(Parameters.Keys, keys);

                    context.Response = response;
                }
            }

            /// <summary>
            /// Contains the logic responsible of processing cryptography responses and invoking the corresponding event handlers.
            /// </summary>
            public class ApplyCryptographyResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
            {
                private readonly IOpenIddictServerProvider _provider;

                public ApplyCryptographyResponse([NotNull] IOpenIddictServerProvider provider)
                    => _provider = provider;

                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                        .UseScopedHandler<ApplyCryptographyResponse<TContext>>()
                        .SetOrder(int.MaxValue - 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public async ValueTask HandleAsync([NotNull] TContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    if (context.EndpointType != OpenIddictServerEndpointType.Cryptography)
                    {
                        return;
                    }

                    var notification = new ApplyCryptographyResponseContext(context.Transaction);
                    await _provider.DispatchAsync(notification);

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

                    throw new InvalidOperationException(new StringBuilder()
                        .Append("The cryptography response was not correctly applied. To apply cryptography response, ")
                        .Append("create a class implementing 'IOpenIddictServerHandler<ApplyCryptographyResponseContext>' ")
                        .AppendLine("and register it using 'services.AddOpenIddict().AddServer().AddEventHandler()'.")
                        .ToString());
                }
            }

            /// <summary>
            /// Contains the logic responsible of attaching the signing keys to the JWKS document.
            /// </summary>
            public class AttachSigningKeys : IOpenIddictServerHandler<HandleCryptographyRequestContext>
            {
                /// <summary>
                /// Gets the default descriptor definition assigned to this handler.
                /// </summary>
                public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                    = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleCryptographyRequestContext>()
                        .UseSingletonHandler<AttachSigningKeys>()
                        .SetOrder(int.MinValue + 100_000)
                        .Build();

                /// <summary>
                /// Processes the event.
                /// </summary>
                /// <param name="context">The context associated with the event to process.</param>
                /// <returns>
                /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
                /// </returns>
                public ValueTask HandleAsync([NotNull] HandleCryptographyRequestContext context)
                {
                    if (context == null)
                    {
                        throw new ArgumentNullException(nameof(context));
                    }

                    foreach (var credentials in context.Options.SigningCredentials)
                    {
#if SUPPORTS_ECDSA
                        if (!IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.RsaSha256) &&
                            !IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.RsaSsaPssSha256) &&
                            !IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.EcdsaSha256) &&
                            !IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.EcdsaSha384) &&
                            !IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.EcdsaSha512))
                        {
                            context.Logger.LogInformation("An unsupported signing key of type '{Type}' was ignored and excluded " +
                                                          "from the key set. Only RSA and ECDSA asymmetric security keys can be " +
                                                          "exposed via the JWKS endpoint.", credentials.Key.GetType().Name);

                            continue;
                        }
#else
                        if (!IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.RsaSha256) &&
                            !IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.RsaSsaPssSha256))
                        {
                            context.Logger.LogInformation("An unsupported signing key of type '{Type}' was ignored and excluded " +
                                                          "from the key set. Only RSA asymmetric security keys can be exposed " +
                                                          "via the JWKS endpoint.", credentials.Key.GetType().Name);

                            continue;
                        }
#endif

                        var key = new JsonWebKey
                        {
                            Use = JsonWebKeyUseNames.Sig,

                            // Resolve the JWA identifier from the algorithm specified in the credentials.
                            Alg = credentials.Algorithm switch
                            {
#if SUPPORTS_ECDSA
                                SecurityAlgorithms.EcdsaSha256 => SecurityAlgorithms.EcdsaSha256,
                                SecurityAlgorithms.EcdsaSha384 => SecurityAlgorithms.EcdsaSha384,
                                SecurityAlgorithms.EcdsaSha512 => SecurityAlgorithms.EcdsaSha512,
                                SecurityAlgorithms.EcdsaSha256Signature => SecurityAlgorithms.EcdsaSha256,
                                SecurityAlgorithms.EcdsaSha384Signature => SecurityAlgorithms.EcdsaSha384,
                                SecurityAlgorithms.EcdsaSha512Signature => SecurityAlgorithms.EcdsaSha512,
#endif
                                SecurityAlgorithms.RsaSha256 => SecurityAlgorithms.RsaSha256,
                                SecurityAlgorithms.RsaSha384 => SecurityAlgorithms.RsaSha384,
                                SecurityAlgorithms.RsaSha512 => SecurityAlgorithms.RsaSha512,
                                SecurityAlgorithms.RsaSha256Signature => SecurityAlgorithms.RsaSha256,
                                SecurityAlgorithms.RsaSha384Signature => SecurityAlgorithms.RsaSha384,
                                SecurityAlgorithms.RsaSha512Signature => SecurityAlgorithms.RsaSha512,

                                SecurityAlgorithms.RsaSsaPssSha256 => SecurityAlgorithms.RsaSsaPssSha256,
                                SecurityAlgorithms.RsaSsaPssSha384 => SecurityAlgorithms.RsaSsaPssSha384,
                                SecurityAlgorithms.RsaSsaPssSha512 => SecurityAlgorithms.RsaSsaPssSha512,
                                SecurityAlgorithms.RsaSsaPssSha256Signature => SecurityAlgorithms.RsaSsaPssSha256,
                                SecurityAlgorithms.RsaSsaPssSha384Signature => SecurityAlgorithms.RsaSsaPssSha384,
                                SecurityAlgorithms.RsaSsaPssSha512Signature => SecurityAlgorithms.RsaSsaPssSha512,

                                _ => null
                            },

                            // Use the key identifier specified in the signing credentials.
                            Kid = credentials.Kid
                        };

                        if (IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.RsaSha256) ||
                            IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.RsaSsaPssSha256))
                        {
                            // Note: IdentityModel 5 doesn't expose a method allowing to retrieve the underlying algorithm
                            // from a generic asymmetric security key. To work around this limitation, try to cast
                            // the security key to the built-in IdentityModel types to extract the required RSA instance.
                            // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/395.

                            var parameters = credentials.Key switch
                            {
                                X509SecurityKey x509SecurityKey when x509SecurityKey.PublicKey is RSA algorithm =>
                                    algorithm.ExportParameters(includePrivateParameters: false),

                                RsaSecurityKey rsaSecurityKey when rsaSecurityKey.Rsa != null =>
                                    rsaSecurityKey.Rsa.ExportParameters(includePrivateParameters: false),

                                RsaSecurityKey rsaSecurityKey => rsaSecurityKey.Parameters,

                                _ => (RSAParameters?) null
                            };

                            if (parameters == null)
                            {
                                context.Logger.LogWarning("A signing key of type '{Type}' was ignored because its RSA public " +
                                                          "parameters couldn't be extracted.", credentials.Key.GetType().Name);

                                continue;
                            }

                            Debug.Assert(parameters.Value.Exponent != null &&
                                         parameters.Value.Modulus != null,
                                "RSA.ExportParameters() shouldn't return a null exponent/modulus.");

                            key.Kty = JsonWebAlgorithmsKeyTypes.RSA;

                            // Note: both E and N must be base64url-encoded.
                            // See https://tools.ietf.org/html/rfc7518#section-6.3.1.1
                            key.E = Base64UrlEncoder.Encode(parameters.Value.Exponent);
                            key.N = Base64UrlEncoder.Encode(parameters.Value.Modulus);
                        }

#if SUPPORTS_ECDSA
                        else if (IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.EcdsaSha256) ||
                                 IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.EcdsaSha384) ||
                                 IsAlgorithmSupported(credentials.Key, SecurityAlgorithms.EcdsaSha512))
                        {
                            var parameters = credentials.Key switch
                            {
                                X509SecurityKey x509SecurityKey when x509SecurityKey.PublicKey is ECDsa algorithm =>
                                    algorithm.ExportParameters(includePrivateParameters: false),

                                ECDsaSecurityKey ecdsaSecurityKey when ecdsaSecurityKey.ECDsa != null =>
                                    ecdsaSecurityKey.ECDsa.ExportParameters(includePrivateParameters: false),

                                _ => (ECParameters?) null
                            };

                            if (parameters == null)
                            {
                                context.Logger.LogWarning("A signing key of type '{Type}' was ignored because its EC public " +
                                                          "parameters couldn't be extracted.", credentials.Key.GetType().Name);

                                continue;
                            }

                            Debug.Assert(parameters.Value.Q.X != null &&
                                         parameters.Value.Q.Y != null,
                                "ECDsa.ExportParameters() shouldn't return null coordinates.");

                            Debug.Assert(parameters.Value.Curve.IsNamed,
                                "ECDsa.ExportParameters() shouldn't return an unnamed curve.");

                            key.Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;
                            key.Crv = IsCurve(parameters.Value, ECCurve.NamedCurves.nistP256) ? JsonWebKeyECTypes.P256 :
                                      IsCurve(parameters.Value, ECCurve.NamedCurves.nistP384) ? JsonWebKeyECTypes.P384 :
                                      IsCurve(parameters.Value, ECCurve.NamedCurves.nistP521) ? JsonWebKeyECTypes.P521 : null;

                            // Note: both X and Y must be base64url-encoded.
                            // See https://tools.ietf.org/html/rfc7518#section-6.2.1.2
                            key.X = Base64UrlEncoder.Encode(parameters.Value.Q.X);
                            key.Y = Base64UrlEncoder.Encode(parameters.Value.Q.Y);
                        }
#endif

                        // If the signing key is embedded in a X.509 certificate, set
                        // the x5t and x5c parameters using the certificate details.
                        var certificate = (credentials.Key as X509SecurityKey)?.Certificate;
                        if (certificate != null)
                        {
                            // x5t must be base64url-encoded.
                            // See https://tools.ietf.org/html/rfc7517#section-4.8
                            key.X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());

                            // x5t#S256 must be base64url-encoded.
                            // See https://tools.ietf.org/html/rfc7517#section-4.9
                            key.X5tS256 = Base64UrlEncoder.Encode(GetCertificateHash(certificate, HashAlgorithmName.SHA256));

                            // Unlike E or N, the certificates contained in x5c
                            // must be base64-encoded and not base64url-encoded.
                            // See https://tools.ietf.org/html/rfc7517#section-4.7
                            key.X5c.Add(Convert.ToBase64String(certificate.RawData));
                        }

                        context.Keys.Add(key);
                    }

                    return default;

                    static bool IsAlgorithmSupported(SecurityKey key, string algorithm) =>
                        key.CryptoProviderFactory.IsSupportedAlgorithm(algorithm, key);

#if SUPPORTS_ECDSA
                    static bool IsCurve(ECParameters parameters, ECCurve curve) =>
                        string.Equals(parameters.Curve.Oid.FriendlyName, curve.Oid.FriendlyName, StringComparison.Ordinal);
#endif

                    static byte[] GetCertificateHash(X509Certificate2 certificate, HashAlgorithmName algorithm)
                    {
#if SUPPORTS_CERTIFICATE_HASHING_WITH_SPECIFIED_ALGORITHM
                        return certificate.GetCertHash(algorithm);
#else
                        using var hash = CryptoConfig.CreateFromName(algorithm.Name) as HashAlgorithm;
                        if (hash == null || hash is KeyedHashAlgorithm)
                        {
                            throw new InvalidOperationException("The specified hash algorithm is not valid.");
                        }

                        return hash.ComputeHash(certificate.RawData);
#endif
                    }
                }
            }
        }
    }
}
