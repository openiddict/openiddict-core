/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using OpenIddict.Extensions;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.Maui.OpenIddictClientMauiConstants;

#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;
#endif

namespace OpenIddict.Client.Maui;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientMauiHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
        /*
         * Top-level request processing:
         */
        InferEndpointType.Descriptor,

        /*
         * Redirection request handling:
         */
        ValidateProcessIdentifier.Descriptor,
        ValidateRequestForgeryProtection.Descriptor,
        ValidateRedirectUri.Descriptor,
        CompleteAuthenticationDemand.Descriptor,

        /*
         * Challenge processing:
         */
        AttachProcessIdentifier.Descriptor,
        
        AbortAuthenticationDemand.Descriptor)
        .AddRange(Authentication.DefaultHandlers);

    /// <summary>
    /// Contains the logic responsible for inferring the endpoint type from the instance activation event.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class InferEndpointType : IOpenIddictClientHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireMauiApplication>()
                .UseSingletonHandler<InferEndpointType>()
                .SetOrder(int.MinValue + 50_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var uri = GetProtocolActivationUri(context.Transaction);

            // Determine the type of endpoint based on the URI resolved from the protocol activation event, which
            // may have been triggered as part of the initial application launch or by an instance redirection.
            context.EndpointType = Matches(uri, context.Options.RedirectionEndpointUris) ? OpenIddictClientEndpointType.Redirection :
                                                                                           OpenIddictClientEndpointType.Unknown;

            return default;

            static bool Matches(Uri uri, IReadOnlyList<Uri> addresses)
            {
                for (var index = 0; index < addresses.Count; index++)
                {
                    var address = addresses[index];
                    if (address.IsAbsoluteUri)
                    {
                        if (string.Equals(address.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(address.Host, uri.Host, StringComparison.OrdinalIgnoreCase) &&
                            string.Equals(address.AbsolutePath, uri.AbsolutePath, StringComparison.OrdinalIgnoreCase) &&
                            address.Port == uri.Port)
                        {
                            return true;
                        }
                    }

                    else if (string.Equals(address.OriginalString, uri.AbsolutePath, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }

                return false;
            }

            static Uri GetProtocolActivationUri(OpenIddictClientTransaction transaction)
            {
#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
                var arguments = transaction.GetProperty<IProtocolActivatedEventArgs>(typeof(IProtocolActivatedEventArgs).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0342));

                return arguments.Uri;
#else
#error The targeted MAUI platform is not supported.
#endif
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from activation events.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class ExtractActivationParameters<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireMauiApplication>()
                .UseSingletonHandler<ExtractActivationParameters<TContext>>()
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

            // Extract the parameters from the query string present in the protocol activation URI.
            context.Transaction.Request = new OpenIddictRequest(OpenIddictHelpers.ParseQuery(GetProtocolActivationUri().Query));

            return default;

            Uri GetProtocolActivationUri()
            {
#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
                var arguments = context.Transaction.GetProperty<IProtocolActivatedEventArgs>(typeof(IProtocolActivatedEventArgs).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0342));

                return arguments.Uri;
#else
#error The targeted MAUI platform is not supported.
#endif
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the process identifier to ensure the instance
    /// that is currently handling the authentication demand is the one that started the process.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class ValidateProcessIdentifier : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireMauiApplication>()
                .UseSingletonHandler<ValidateProcessIdentifier>()
                .SetOrder(ValidateStateToken.Descriptor.Order + 500)
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

            var identifier = context.StateTokenPrincipal.GetClaim(Claims.Private.ProcessId);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0341));
            }

#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
            switch (AppInstance.GetInstances()
                .FirstOrDefault(instance => instance.ProcessId == int.Parse(identifier, CultureInfo.InvariantCulture)))
            {
                // If the instance corresponding to the process identifier stored in the state token
                // cannot be resolved, this likely means that the instance has been terminated after
                // the authorization process started. This could also mean that the received response
                // uses a state token meant to be used with a different authentication operation and
                // may be a session fixation attack. In any case, the authentication demand cannot
                // be processed by any valid instance and the current instance must be terminated.
                case null:
                    Environment.Exit(0);
                    break;

                // If the instance corresponding to the process identifier stored in the state token
                // is not the current one, stop processing the authentication demand in this instance
                // and redirect the protocol arguments to the correct instance. Once the redirection
                // has been processed by the other instance, immediately terminate the current instance.
                case { IsCurrent: false } instance:
                    await instance.RedirectActivationToAsync(AppInstance.GetCurrent().GetActivatedEventArgs());
                    Environment.Exit(0);
                    break;

                // Otherwise, let the current instance process the authentication demand.
            }
#endif
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the request forgery protection that serves as a
    /// protection against state token injection, forged requests and session fixation attacks.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class ValidateRequestForgeryProtection : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientMauiAuthenticator _authenticator;

        public ValidateRequestForgeryProtection(OpenIddictClientMauiAuthenticator authenticator)
            => _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireMauiApplication>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ValidateRequestForgeryProtection>()
                .SetOrder(ValidateProcessIdentifier.Descriptor.Order + 50)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Resolve the request forgery protection from the state token principal.
            var identifier = context.StateTokenPrincipal.GetClaim(Claims.RequestForgeryProtection);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0339));
            }

            // Ensure the authentication demand is tracked by the OpenIddict client MAUI authenticator.
            // If it's not, this may indicate a session fixation attack: in this case, abort the process.
            if (!_authenticator.TryValidate(identifier))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2139),
                    uri: SR.FormatID8000(SR.ID2139));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for comparing the current request URL to the redirect_uri stored in the state token.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class ValidateRedirectUri : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireMauiApplication>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ValidateRedirectUri>()
                .SetOrder(ValidateRequestForgeryProtection.Descriptor.Order + 50)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Try to resolve the original redirect_uri from the state token. If it cannot be resolved,
            // this likely means the authorization request was sent without a redirect_uri attached.
            if (!Uri.TryCreate(context.StateTokenPrincipal.GetClaim(Claims.Private.RedirectUri),
                UriKind.Absolute, out Uri? address))
            {
                return default;
            }

            // Resolve the protocol activation URI and extract the parameters from its query string.
            var uri = GetProtocolActivationUri();
            var parameters = OpenIddictHelpers.ParseQuery(uri.Query);

            // Compare the protocol activation URI address to the original redirect_uri. If the two don't
            // match, this may indicate a mix-up attack. While the authorization server is expected to
            // abort the authorization flow by rejecting the token request that may be eventually sent
            // with the original redirect_uri, many servers are known to incorrectly implement this
            // redirect_uri validation logic. This check also offers limited protection as it cannot
            // prevent the authorization code from being leaked to a malicious authorization server.
            // By comparing the redirect_uri directly in the client, a first layer of protection is
            // provided independently of whether the authorization server will enforce this check.
            //
            // See https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-19#section-4.4.2.2
            // for more information.
            if (new UriBuilder(uri) { Query = null }.Uri != new UriBuilder(address) { Query = null }.Uri)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2138),
                    uri: SR.FormatID8000(SR.ID2138));

                return default;
            }

            // Ensure all the query string parameters that were part of the original redirect_uri
            // are present in the current request (parameters that were not part of the original
            // redirect_uri are assumed to be authorization response parameters and are ignored).
            if (!string.IsNullOrEmpty(address.Query) && OpenIddictHelpers.ParseQuery(address.Query)
                .Any(parameter => parameters[parameter.Key] != parameter.Value))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2138),
                    uri: SR.FormatID8000(SR.ID2138));

                return default;
            }

            return default;

            Uri GetProtocolActivationUri()
            {
#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
                var arguments = context.Transaction.GetProperty<IProtocolActivatedEventArgs>(typeof(IProtocolActivatedEventArgs).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0342));

                return arguments.Uri;
#else
#error The targeted MAUI platform is not supported.
#endif
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the authentication service the demand is complete.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class CompleteAuthenticationDemand : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        private readonly OpenIddictClientMauiAuthenticator _authenticator;

        public CompleteAuthenticationDemand(OpenIddictClientMauiAuthenticator authenticator)
            => _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireMauiApplication>()
                .UseSingletonHandler<CompleteAuthenticationDemand>()
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

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            var identifier = context.StateTokenPrincipal.GetClaim(Claims.RequestForgeryProtection);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0339));
            }

            // A single main claims-based principal instance can be attached to an authentication ticket.
            // To return the most appropriate one, the principal is selected based on the endpoint type.
            // Independently of the selected main principal, all principals resolved from validated tokens
            // are attached to the authentication properties bag so they can be accessed from user code.
            var principal = context.EndpointType switch
            {
                // Create a composite principal containing claims resolved from the frontchannel
                // and backchannel identity tokens and the userinfo token principal, if available.
                OpenIddictClientEndpointType.Redirection => OpenIddictHelpers.CreateMergedPrincipal(
                    context.FrontchannelIdentityTokenPrincipal,
                    context.BackchannelIdentityTokenPrincipal,
                    context.UserinfoTokenPrincipal),

                _ => null
            };

            if (principal is null)
            {
                return default;
            }

            // Attach the identity of the authorization to the returned principal to allow resolving it even if no other
            // claim was added to the principal (e.g when no id_token was returned and no userinfo endpoint is available).
            principal.SetClaim(Claims.AuthorizationServer, context.StateTokenPrincipal?.GetClaim(Claims.AuthorizationServer));

            var properties = new Dictionary<string, string>(StringComparer.Ordinal);

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                properties[Tokens.AuthorizationCode] = context.AuthorizationCode;
            }

            if (!string.IsNullOrEmpty(context.BackchannelAccessToken))
            {
                properties[Tokens.BackchannelAccessToken] = context.BackchannelAccessToken;
            }

            if (!string.IsNullOrEmpty(context.BackchannelIdentityToken))
            {
                properties[Tokens.BackchannelIdentityToken] = context.BackchannelIdentityToken;
            }

            if (!string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                properties[Tokens.FrontchannelAccessToken] = context.FrontchannelAccessToken;
            }

            if (!string.IsNullOrEmpty(context.FrontchannelIdentityToken))
            {
                properties[Tokens.FrontchannelIdentityToken] = context.FrontchannelIdentityToken;
            }

            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                properties[Tokens.RefreshToken] = context.RefreshToken;
            }

            if (!string.IsNullOrEmpty(context.StateToken))
            {
                properties[Tokens.StateToken] = context.StateToken;
            }

            if (!string.IsNullOrEmpty(context.UserinfoToken))
            {
                properties[Tokens.UserinfoToken] = context.UserinfoToken;
            }

            // Note: while OpenIddict uses two distinct tokens for the frontchannel and backchannel properties,
            // WebAuthenticatorResult only exposes generic access_token and id_token properties. To work around
            // that, the backchannel access/identity tokens are chosen first and the frontchannel tokens (i.e
            // returned directly in the authorization response) are used if no backchannel token is present.
            if (!string.IsNullOrEmpty(context.BackchannelAccessToken))
            {
                properties[Parameters.AccessToken] = context.BackchannelAccessToken;
            }

            else if (!string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                properties[Parameters.AccessToken] = context.FrontchannelAccessToken;
            }

            if (!string.IsNullOrEmpty(context.BackchannelIdentityToken))
            {
                properties[Parameters.IdToken] = context.BackchannelIdentityToken;
            }

            else if (!string.IsNullOrEmpty(context.FrontchannelIdentityToken))
            {
                properties[Parameters.IdToken] = context.FrontchannelIdentityToken;
            }

            // Try to inform the authenticator that the authentication demand is complete.
            _authenticator.TryComplete(identifier, new OpenIddictClientMauiAuthenticatorResult(principal, properties));

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for storing the identifier of the current process in the state token.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class AttachProcessIdentifier : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireMauiApplication>()
                .AddFilter<RequireStateTokenGenerated>()
                .UseSingletonHandler<AttachProcessIdentifier>()
                .SetOrder(PrepareStateTokenPrincipal.Descriptor.Order + 500)
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

#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
            // By default, WinUI-based applications are multi-instanced applications. As such, any protocol activation
            // triggered by visiting one of the URIs associated with the application and configured in the OpenIddict
            // client options will create a new application instance, different from the one that initially started
            // the authentication flow. To deal with that without having to share persistent state between instances,
            // OpenIddict stores the process identifier of the instance that starts the authentication process and
            // uses it when handling the callback to determine whether the protocol activation should be redirected
            // to a different instance using Project Reunion's AppInstance.RedirectActivationToAsync() API.

            context.StateTokenPrincipal.SetClaim(Claims.Private.ProcessId,
                AppInstance.GetCurrent().ProcessId.ToString(CultureInfo.InvariantCulture));
#endif

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for informing the authentication service the demand is aborted.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class AbortAuthenticationDemand : IOpenIddictClientHandler<ProcessErrorContext>
    {
        private readonly OpenIddictClientMauiAuthenticator _authenticator;

        public AbortAuthenticationDemand(OpenIddictClientMauiAuthenticator authenticator)
            => _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .AddFilter<RequireMauiApplication>()
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

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            // Try to resolve the state token principal from the authentication event context, if available.
            // If the principal is available, resolve the "rfp" claim used by the MAUI authenticator service
            // to track pending authentication operations and mark the correct one as failed.
            if (notification?.StateTokenPrincipal is ClaimsPrincipal principal)
            {
                var identifier = principal.GetClaim(Claims.RequestForgeryProtection);
                if (string.IsNullOrEmpty(identifier))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0339));
                }

                // Try to inform the authenticator that the operation failed.
                _authenticator.TryAbort(identifier, new ProtocolException(
                    SR.GetResourceString(SR.ID0340),
                    context.Error, context.ErrorDescription, context.ErrorUri));
            }

#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
            // If the current application instance was created to react to a protocol activation (assumed to be
            // managed by OpenIddict at this stage), terminate it to prevent the main window from being activated.
            // By doing that, unsolicited authorization responses will be ignored without the user seeing it.
            if (AppInstance.GetCurrent().GetActivatedEventArgs() is { Kind: ExtendedActivationKind.Protocol })
            {
                Environment.Exit(0);
            }
#endif

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing context responses that must be returned as plain-text.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by MAUI.
    /// </summary>
    public class ProcessResponse<TContext> : IOpenIddictClientHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireMauiApplication>()
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
