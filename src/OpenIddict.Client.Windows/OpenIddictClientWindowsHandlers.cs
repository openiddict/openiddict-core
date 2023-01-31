/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Claims;
using System.Security.Principal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;

#if !SUPPORTS_HOST_APPLICATION_LIFETIME
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace OpenIddict.Client.Windows;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientWindowsHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Top-level request processing:
         */
        ResolveRequestUri.Descriptor,

        /*
         * Authentication processing:
         */
        WaitMarshalledAuthentication.Descriptor,
        RestoreStateTokenFromMarshalledAuthentication.Descriptor,
        RestoreStateTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreClientRegistrationFromMarshalledContext.Descriptor,
        RedirectProtocolActivation.Descriptor,
        ResolveRequestForgeryProtection.Descriptor,
        RestoreFrontchannelTokensFromMarshalledAuthentication.Descriptor,
        RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreAuthorizationCodePrincipalFromMarshalledAuthentication.Descriptor,
        RestoreBackchannelTokensFromMarshalledAuthentication.Descriptor,
        RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreRefreshTokenPrincipalFromMarshalledAuthentication.Descriptor,
        RestoreUserinfoDetailsFromMarshalledAuthentication.Descriptor,
        CompleteAuthenticationOperation.Descriptor,
        UntrackMarshalledAuthenticationOperation.Descriptor,

        /*
         * Challenge processing:
         */
        InferBaseUriFromClientUri.Descriptor,
        AttachInstanceIdentifier.Descriptor,
        TrackAuthenticationOperation.Descriptor,

        /*
         * Error processing:
         */
        AbortAuthenticationDemand.Descriptor)
        .AddRange(Authentication.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the protocol activation details.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class ResolveRequestUri : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireWindowsActivation>()
                .UseSingletonHandler<ResolveRequestUri>()
                .SetOrder(int.MinValue + 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.BaseUri, context.RequestUri) = context.Transaction.GetWindowsActivation() switch
            {
                null => throw new InvalidOperationException(SR.GetResourceString(SR.ID0375)),

                // In most cases, the first segment present in the command line arguments contains the path of the
                // executable, but it's technically possible to start an application in a way that the command line
                // arguments will never include the executable path. To support both cases, the URI is extracted
                // from the second segment when 2 segments are present. Otherwise, the first segment is used.
                //
                // For more information, see https://devblogs.microsoft.com/oldnewthing/20060515-07/?p=31203.

                { ActivationArguments: [_, string argument] } when Uri.TryCreate(argument, UriKind.Absolute, out Uri? uri) &&
                    !uri.IsFile && uri.IsWellFormedOriginalString()
                    => (new Uri(uri.GetLeftPart(UriPartial.Authority), UriKind.Absolute), uri),

                { ActivationArguments: [string argument] } when Uri.TryCreate(argument, UriKind.Absolute, out Uri? uri) &&
                    !uri.IsFile && uri.IsWellFormedOriginalString()
                    => (new Uri(uri.GetLeftPart(UriPartial.Authority), UriKind.Absolute), uri),

                // If no protocol activation URI could be resolved, use fake static URIs.
                _ => (new Uri("local://", UriKind.Absolute), new Uri("local://", UriKind.Absolute))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from the request URI.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class ExtractRequestUriParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireWindowsActivation>()
                .UseSingletonHandler<ExtractRequestUriParameters<TContext>>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Extract the parameters from the query string present in the request URI.
            context.Transaction.Request = new OpenIddictRequest(context.RequestUri switch
            {
                { IsAbsoluteUri: true } uri => OpenIddictHelpers.ParseQuery(uri.Query),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0127))
            });

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for waiting for the marshalled authentication operation to complete, if applicable.
    /// </summary>
    public sealed class WaitMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;
        private readonly IOptionsMonitor<OpenIddictClientWindowsOptions> _options;

        public WaitMarshalledAuthentication(
            OpenIddictClientWindowsMarshaller marshaller,
            IOptionsMonitor<OpenIddictClientWindowsOptions> options)
        {
            _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<WaitMarshalledAuthentication>()
                .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Skip the marshalling logic entirely if the operation is not tracked.
            if (!_marshaller.IsTracked(context.Nonce))
            {
                return;
            }

            // Allow a single authentication operation at the same time with the same nonce.
            if (!_marshaller.TryAcquireLock(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0379));
            }

            // At this point, user authentication demands cannot complete until the authorization response has been
            // returned to the redirection endpoint (materialized as a registered protocol activation URI) and handled
            // by OpenIddict via the ProcessRequest event. Since it is asynchronous by nature, this process requires
            // using a signal mechanism to unblock the authentication operation once it is complete. For that, the
            // marshaller uses a TaskCompletionSource (one per authentication) that will be automatically completed
            // or aborted by a specialized event handler as part of the ProcessRequest/ProcessError events processing.

            try
            {
                // To ensure pending authentication operations for which no response is received are not tracked
                // indefinitely, a CancellationTokenSource with a static timeout is used even if the cancellation
                // token specified by the user is never marked as canceled: if the authentication is not completed
                // when the timeout is reached, the operation will be considered canceled and removed from the list.
                using var source = CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
                source.CancelAfter(_options.CurrentValue.AuthenticationTimeout);

                if (!await _marshaller.TryWaitForCompletionAsync(context.Nonce, source.Token) ||
                    !_marshaller.TryGetResult(context.Nonce, out ProcessAuthenticationContext? notification))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0383));
                }

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
            }

            // If the operation failed due to the timeout, it's likely the TryRemove() method
            // won't be called, so the tracked context is manually removed before re-throwing.
            catch (OperationCanceledException) when (_marshaller.TryRemove(context.Nonce))
            {
                throw;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the state token from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreStateTokenFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreStateTokenFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreStateTokenFromMarshalledAuthentication>()
                .SetOrder(ResolveValidatedStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.StateToken = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the state token from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.StateToken,

                // Otherwise, don't alter the current context.
                _ => context.StateToken
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the state token
    /// principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreStateTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreStateTokenPrincipalFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreStateTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.StateTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore
                // the state token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.StateTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.StateTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the client registration and
    /// configuration from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreClientRegistrationFromMarshalledContext : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreClientRegistrationFromMarshalledContext(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreClientRegistrationFromMarshalledContext>()
                .SetOrder(ResolveClientRegistrationFromStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.Issuer, context.Configuration, context.Registration) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // issuer registration and configuration from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => (notification.Issuer, notification.Configuration, notification.Registration),

                _ => (context.Issuer, context.Configuration, context.Registration)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for redirecting the Windows protocol activation
    /// to the instance that initially started the authentication demand, if applicable.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class RedirectProtocolActivation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly IHostApplicationLifetime _lifetime;
        private readonly IOptionsMonitor<OpenIddictClientWindowsOptions> _options;

        public RedirectProtocolActivation(
            IHostApplicationLifetime lifetime,
            IOptionsMonitor<OpenIddictClientWindowsOptions> options)
        {
            _lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireWindowsActivation>()
                .AddFilter<RequireStateTokenPrincipal>()
                .UseSingletonHandler<RedirectProtocolActivation>()
                .SetOrder(ResolveNonceFromStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            var identifier = context.StateTokenPrincipal.GetClaim(Claims.Private.InstanceId);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0376));
            }

            // If the identifier stored in the state token doesn't match the identifier of the
            // current instance, stop processing the authentication demand in this process and
            // redirect the protocol activation to the correct instance. Once the redirection
            // has been received by the other instance, ask the host to stop the application.
            if (!string.Equals(identifier, _options.CurrentValue.InstanceIdentifier, StringComparison.OrdinalIgnoreCase))
            {
                var activation = context.Transaction.GetWindowsActivation() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0375));

                using (var buffer = new MemoryStream())
                using (var writer = new BinaryWriter(buffer))
                using (var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(10)))
                using (var stream = new NamedPipeClientStream(
                    serverName        : ".",
                    pipeName          : $@"{_options.CurrentValue.PipeName}\{identifier}",
                    direction         : PipeDirection.Out,
                    options           : PipeOptions.Asynchronous,
                    impersonationLevel: TokenImpersonationLevel.None,
                    inheritability    : HandleInheritability.None))
                {
                    // Wait for the target to accept the pipe connection.
                    await stream.ConnectAsync(source.Token);

                    // Write the type of message stored in the shared memory and the
                    // version used to identify the binary serialization format.
                    writer.Write(0x01);
                    writer.Write(0x01);

                    // Write the number of arguments present in the activation.
                    writer.Write(activation.ActivationArguments.Length);

                    // Write all the arguments present in the activation.
                    for (var index = 0; index < activation.ActivationArguments.Length; index++)
                    {
                        writer.Write(activation.ActivationArguments[index]);
                    }

                    // Transfer the payload to the target.
                    buffer.Seek(0L, SeekOrigin.Begin);
                    await buffer.CopyToAsync(stream, bufferSize: 81_920, source.Token);
                }

                // Inform the host that the application should stop and mark the authentication context as handled
                // to prevent the other event handlers from being invoked while the application is shutting down.
                _lifetime.StopApplication();
                context.HandleRequest();

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the request forgery protection that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class ResolveRequestForgeryProtection : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public ResolveRequestForgeryProtection(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireWindowsActivation>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<ResolveRequestForgeryProtection>()
                .SetOrder(ValidateRequestForgeryProtection.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Ensure the authentication demand is tracked by the OpenIddict client Windows marshaller
            // and resolve the corresponding request forgery protection. If it can't be found, this may
            // indicate a session fixation attack: in this case, reject the authentication demand.
            if (!_marshaller.TryGetRequestForgeryProtection(context.Nonce, out string? protection))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2139),
                    uri: SR.FormatID8000(SR.ID2139));

                return default;
            }

            context.RequestForgeryProtection = protection;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel tokens from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreFrontchannelTokensFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreFrontchannelTokensFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreFrontchannelTokensFromMarshalledAuthentication>()
                .SetOrder(ResolveValidatedFrontchannelTokens.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.AuthorizationCode,
             context.FrontchannelAccessToken,
             context.FrontchannelIdentityToken) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the tokens from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => (notification.AuthorizationCode, notification.FrontchannelAccessToken, notification.FrontchannelIdentityToken),

                // Otherwise, don't alter the current context.
                _ => (context.AuthorizationCode, context.FrontchannelAccessToken, context.FrontchannelIdentityToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel identity
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreFrontchannelIdentityTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateFrontchannelIdentityToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.FrontchannelIdentityTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel identity token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.FrontchannelIdentityTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.FrontchannelIdentityTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel access
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreFrontchannelAccessTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateFrontchannelAccessToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.FrontchannelAccessTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel access token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.FrontchannelAccessTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.FrontchannelAccessTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the authorization code
    /// principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreAuthorizationCodePrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreAuthorizationCodePrincipalFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreAuthorizationCodePrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateAuthorizationCode.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.AuthorizationCodePrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // authorization code principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.AuthorizationCodePrincipal,

                // Otherwise, don't alter the current context.
                _ => context.AuthorizationCodePrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the token response from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreTokenResponseFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreTokenResponseFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreTokenResponseFromMarshalledAuthentication>()
                .SetOrder(SendTokenRequest.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.TokenResponse = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the token response from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.TokenResponse,

                // Otherwise, don't alter the current context.
                _ => context.TokenResponse
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the backchannel tokens from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreBackchannelTokensFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreBackchannelTokensFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreBackchannelTokensFromMarshalledAuthentication>()
                .SetOrder(ResolveValidatedBackchannelTokens.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.BackchannelAccessToken,
             context.BackchannelIdentityToken,
             context.RefreshToken) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the tokens from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => (notification.BackchannelAccessToken, notification.BackchannelIdentityToken, notification.RefreshToken),

                // Otherwise, don't alter the current context.
                _ => (context.BackchannelAccessToken, context.BackchannelIdentityToken, context.RefreshToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the backchannel identity
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreBackchannelIdentityTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateBackchannelIdentityToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.BackchannelIdentityTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel identity token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.BackchannelIdentityTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.BackchannelIdentityTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the frontchannel access
    /// token principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreBackchannelAccessTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateBackchannelAccessToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.BackchannelAccessTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the
                // frontchannel access token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.BackchannelAccessTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.BackchannelAccessTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the refresh token
    /// principal from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreRefreshTokenPrincipalFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreRefreshTokenPrincipalFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreRefreshTokenPrincipalFromMarshalledAuthentication>()
                .SetOrder(ValidateRefreshToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            context.RefreshTokenPrincipal = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore
                // the refresh token principal from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => notification.RefreshTokenPrincipal,

                // Otherwise, don't alter the current context.
                _ => context.RefreshTokenPrincipal
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for restoring the userinfo details
    /// from the marshalled authentication context, if applicable.
    /// </summary>
    public sealed class RestoreUserinfoDetailsFromMarshalledAuthentication : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public RestoreUserinfoDetailsFromMarshalledAuthentication(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<RestoreUserinfoDetailsFromMarshalledAuthentication>()
                .SetOrder(SendUserinfoRequest.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            (context.UserinfoResponse, context.UserinfoTokenPrincipal, context.UserinfoToken) = context.EndpointType switch
            {
                // When the authentication context is marshalled, restore the userinfo details from the other instance.
                OpenIddictClientEndpointType.Unknown when _marshaller.TryGetResult(context.Nonce, out var notification)
                    => (notification.UserinfoResponse, notification.UserinfoTokenPrincipal, notification.UserinfoToken),

                // Otherwise, don't alter the current context.
                _ => (context.UserinfoResponse, context.UserinfoTokenPrincipal, context.UserinfoToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the authentication service the operation is complete.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class CompleteAuthenticationOperation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public CompleteAuthenticationOperation(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .AddFilter<RequireWindowsActivation>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<CompleteAuthenticationOperation>()
                .SetOrder(int.MaxValue - 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // Inform the marshaller that the authentication demand is complete.
            if (!_marshaller.TryComplete(context.Nonce, context))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0380));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the marshaller that the context
    /// associated with the authentication operation can be discarded, if applicable.
    /// </summary>
    public sealed class UntrackMarshalledAuthenticationOperation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public UntrackMarshalledAuthenticationOperation(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthenticationNonce>()
                .UseSingletonHandler<UntrackMarshalledAuthenticationOperation>()
                .SetOrder(int.MaxValue)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.Nonce), SR.GetResourceString(SR.ID4019));

            // If applicable, inform the marshaller that the authentication demand can be discarded.
            if (context.EndpointType is OpenIddictClientEndpointType.Unknown &&
                _marshaller.IsTracked(context.Nonce) && !_marshaller.TryRemove(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0381));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for inferring the base URI from the client URI set in the options.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class InferBaseUriFromClientUri : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .UseSingletonHandler<InferBaseUriFromClientUri>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.BaseUri ??= context.Options.ClientUri;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for storing the identifier of the current instance in the state token.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class AttachInstanceIdentifier : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly IOptionsMonitor<OpenIddictClientWindowsOptions> _options;

        public AttachInstanceIdentifier(IOptionsMonitor<OpenIddictClientWindowsOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireLoginStateTokenGenerated>()
                .UseSingletonHandler<AttachInstanceIdentifier>()
                .SetOrder(PrepareLoginStateTokenPrincipal.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Most Windows applications (except WinRT applications) are multi-instanced. As such, any protocol activation
            // triggered by launching one of the URI schemes associated with the application will create a new instance,
            // different from the one that initially started the authentication flow. To deal with that without having to
            // share persistent state between instances, OpenIddict stores the identifier of the instance that starts the
            // authentication process and uses it when handling the callback to determine whether the protocol activation
            // should be redirected to a different instance using inter-process communication.
            context.StateTokenPrincipal.SetClaim(Claims.Private.InstanceId, _options.CurrentValue.InstanceIdentifier);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for asking the marshaller to track the authentication operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class TrackAuthenticationOperation : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;

        public TrackAuthenticationOperation(OpenIddictClientWindowsMarshaller marshaller)
            => _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveSession>()
                .AddFilter<RequireLoginStateTokenGenerated>()
                .UseSingletonHandler<TrackAuthenticationOperation>()
                .SetOrder(int.MaxValue - 50_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.Nonce))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0352));
            }

            if (string.IsNullOrEmpty(context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0343));
            }

            if (!_marshaller.TryAdd(context.Nonce, context.RequestForgeryProtection))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0378));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the authentication service the demand is aborted.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class AbortAuthenticationDemand : IOpenIddictClientHandler<ProcessErrorContext>
    {
        private readonly OpenIddictClientWindowsMarshaller _marshaller;
        private readonly IHostApplicationLifetime _lifetime;

        public AbortAuthenticationDemand(
            OpenIddictClientWindowsMarshaller marshaller,
            IHostApplicationLifetime lifetime)
        {
            _marshaller = marshaller ?? throw new ArgumentNullException(nameof(marshaller));
            _lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .AddFilter<RequireWindowsActivation>()
                .UseSingletonHandler<AbortAuthenticationDemand>()
                .SetOrder(ProcessResponse<ProcessErrorContext>.Descriptor.Order - 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessErrorContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Try to resolve the authentication context from the transaction, if available.
            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!);

            // If the context is available, resolve the nonce used to track the marshalled authentication
            // and inform the marshaller so that the context can be marshalled back to the initiator.
            if (!string.IsNullOrEmpty(notification?.Nonce) && !_marshaller.TryComplete(notification.Nonce, notification))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0382));
            }

            var activation = context.Transaction.GetWindowsActivation() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0375));

            // If the current application instance was created to react to a protocol activation (assumed to be
            // managed by OpenIddict at this stage), terminate it to prevent the UI thread from being started.
            // By doing that, unsolicited requests will be discarded without the user seeing flashing windows.
            if (!activation.IsActivationRedirected)
            {
                _lifetime.StopApplication();
                context.HandleRequest();

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for marking context responses as handled.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
    /// </summary>
    public sealed class ProcessResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireWindowsActivation>()
                .UseSingletonHandler<ProcessResponse<TContext>>()
                .SetOrder(100_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.HandleRequest();

            return default;
        }
    }
}
