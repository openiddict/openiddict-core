/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;

#if SUPPORTS_WINDOWS_RUNTIME
using Windows.Security.Authentication.Web;
#endif

namespace OpenIddict.Client.SystemIntegration;

public static partial class OpenIddictClientSystemIntegrationHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request processing:
             */
            InvokeWebAuthenticationBroker.Descriptor,
            LaunchSystemBrowser.Descriptor,

            /*
             * Redirection request extraction:
             */
            ExtractGetHttpListenerRequest<ExtractRedirectionRequestContext>.Descriptor,
            ExtractProtocolActivationParameters<ExtractRedirectionRequestContext>.Descriptor,
            ExtractWebAuthenticationResultData<ExtractRedirectionRequestContext>.Descriptor,

            /*
             * Redirection response handling:
             */
            AttachHttpResponseCode<ApplyRedirectionResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyRedirectionResponseContext>.Descriptor,
            ProcessEmptyHttpResponse.Descriptor,
            ProcessUnactionableResponse<ApplyRedirectionResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible for initiating authorization requests using the web authentication broker.
        /// Note: this handler is not used when the user session is not interactive.
        /// </summary>
        public class InvokeWebAuthenticationBroker : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            private readonly OpenIddictClientSystemIntegrationService _service;

            public InvokeWebAuthenticationBroker(OpenIddictClientSystemIntegrationService service)
                => _service = service ?? throw new ArgumentNullException(nameof(service));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .AddFilter<RequireWebAuthenticationBroker>()
                    .UseSingletonHandler<InvokeWebAuthenticationBroker>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
#pragma warning disable CS1998
            public async ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
#pragma warning restore CS1998
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

#if SUPPORTS_WINDOWS_RUNTIME
                if (string.IsNullOrEmpty(context.RedirectUri))
                {
                    return;
                }

                // OpenIddict represents the complete interactive authentication dance as a two-phase process:
                //   - The challenge, during which the user is redirected to the authorization server, either
                //     by launching the system browser or, as in this case, using a web-view-like approach.
                //
                //   - The authentication that takes place after the authorization server and the user approved
                //     the demand and redirected the user agent to the client (using either protocol activation,
                //     an embedded web server or by tracking the return URL of the web view created for the process).
                //
                // Unlike OpenIddict, WebAuthenticationBroker materializes this process as a single/one-shot API
                // that opens the system-managed authentication host, navigates to the specified request URI and
                // doesn't return until the specified callback URI is reached or the modal closed by the user.
                // To accomodate OpenIddict's model, successful results are processed as any other callback request.

                try
                {
                    // Note: IAsyncOperation<T>.AsTask(context.CancellationToken) is deliberately not used here as
                    // the asynchronous operation returned by the web authentication broker is not cancellable.
                    switch (await WebAuthenticationBroker.AuthenticateAsync(
                        options    : WebAuthenticationOptions.None,
                        requestUri : OpenIddictHelpers.AddQueryStringParameters(
                            uri: new Uri(context.AuthorizationEndpoint, UriKind.Absolute),
                            parameters: context.Transaction.Request.GetParameters().ToDictionary(
                                parameter => parameter.Key,
                                parameter => new StringValues((string?[]?) parameter.Value))),
                        callbackUri: new Uri(context.RedirectUri, UriKind.Absolute)))
                    {
                        case { ResponseStatus: WebAuthenticationStatus.Success } result:
                            await _service.HandleWebAuthenticationResultAsync(result, context.CancellationToken);
                            context.HandleRequest();
                            return;

                        // Since the result of this operation is known by the time WebAuthenticationBroker.AuthenticateAsync()
                        // returns, some errors can directly be handled and surfaced here, as part of the challenge handling.

                        case { ResponseStatus: WebAuthenticationStatus.UserCancel }:
                            context.Reject(
                                error: Errors.AccessDenied,
                                description: SR.GetResourceString(SR.ID2149),
                                uri: SR.FormatID8000(SR.ID2149));

                            return;

                        case { ResponseStatus: WebAuthenticationStatus.ErrorHttp } result:
                            context.Reject(
                                error: result.ResponseErrorDetail switch
                                {
                                    400 => Errors.InvalidRequest,
                                    401 => Errors.InvalidToken,
                                    403 => Errors.InsufficientAccess,
                                    429 => Errors.SlowDown,
                                    500 => Errors.ServerError,
                                    503 => Errors.TemporarilyUnavailable,
                                    _   => Errors.ServerError
                                },
                                description: SR.FormatID2161(result.ResponseErrorDetail),
                                uri: SR.FormatID8000(SR.ID2161));

                            return;

                        default:
                            context.Reject(
                                error: Errors.ServerError,
                                description: SR.GetResourceString(SR.ID2136),
                                uri: SR.FormatID8000(SR.ID2136));

                            return;
                    }
                }

                catch
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2136),
                        uri: SR.FormatID8000(SR.ID2136));

                    return;
                }
#else
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0392));
#endif
            }
        }

        /// <summary>
        /// Contains the logic responsible for initiating authorization requests using the system browser.
        /// Note: this handler is not used when the user session is not interactive.
        /// </summary>
        public class LaunchSystemBrowser : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .AddFilter<RequireSystemBrowser>()
                    .UseSingletonHandler<LaunchSystemBrowser>()
                    .SetOrder(InvokeWebAuthenticationBroker.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                var uri = OpenIddictHelpers.AddQueryStringParameters(
                    uri: new Uri(context.AuthorizationEndpoint, UriKind.Absolute),
                    parameters: context.Transaction.Request.GetParameters().ToDictionary(
                        parameter => parameter.Key,
                        parameter => new StringValues((string?[]?) parameter.Value)));

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Note: on Windows, multiple application models exist and must be supported to cover most scenarios:
                    //
                    //   - Classical Win32 applications, for which no application-specific restriction is enforced.
                    //   - Win32 applications running in an AppContainer, that are very similar to UWP applications.
                    //   - Classical UWP applications, for which strict application restrictions are enforced.
                    //   - Full-trust UWP applications, that are rare but very similar to classical Win32 applications.
                    //   - Modern/hybrid Windows applications, that can be sandboxed or run as full-trust applications.
                    //
                    // Since .NET Standard 2.0 support for UWP was only introduced in Windows 10 1709 (also known
                    // as Fall Creators Update) and OpenIddict requires Windows 10 1809 as the minimum supported
                    // version, Windows 8/8.1's Metro-style/universal applications are deliberately not supported.
                    //
                    // While Process.Start()/ShellExecuteEx() can typically be used without any particular restriction
                    // by non-sandboxed desktop applications to launch the default system browser, calling these
                    // APIs in sandboxed applications will result in an UnauthorizedAccessException being thrown.
                    //
                    // To avoid that, the OpenIddict host needs to determine whether the platform supports Windows
                    // Runtime APIs and favor the Launcher.LaunchUriAsync() API when it's offered by the platform.

#if SUPPORTS_WINDOWS_RUNTIME
                    if (OpenIddictClientSystemIntegrationHelpers.IsWindowsRuntimeSupported() && await
                        OpenIddictClientSystemIntegrationHelpers.TryLaunchBrowserWithWindowsRuntimeAsync(uri))
                    {
                        context.HandleRequest();
                        return;
                    }
#endif
                    if (await OpenIddictClientSystemIntegrationHelpers.TryLaunchBrowserWithShellExecuteAsync(uri))
                    {
                        context.HandleRequest();
                        return;
                    }
                }

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) &&
                    await OpenIddictClientSystemIntegrationHelpers.TryLaunchBrowserWithXdgOpenAsync(uri))
                {
                    context.HandleRequest();
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0385));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing OpenID Connect responses that don't specify any parameter.
        /// Note: this handler is not used when the OpenID Connect request is not handled by the embedded web server.
        /// </summary>
        public sealed class ProcessEmptyHttpResponse : IOpenIddictClientHandler<ApplyRedirectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyRedirectionResponseContext>()
                    .AddFilter<RequireHttpListenerContext>()
                    .UseSingletonHandler<ProcessEmptyHttpResponse>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyRedirectionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

                // This handler only applies to HTTP listener requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpListenerContext()?.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0390));

                // Always return a 200 status, even for responses indicating that the authentication failed.
                response.StatusCode = 200;
                response.ContentType = "text/plain";

                // Return a message indicating whether the authentication process
                // succeeded or failed and that will be visible by the user.
                var buffer = Encoding.UTF8.GetBytes(context.Transaction.Response.Error switch
                {
                    null or { Length: 0 } => "Login completed. Please return to the application.",
                    Errors.AccessDenied   => "Authorization denied. Please return to the application.",
                    _                     => "Authentication failed. Please return to the application."
                });

#if SUPPORTS_STREAM_MEMORY_METHODS
                await response.OutputStream.WriteAsync(buffer);
#else
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
#endif
                await response.OutputStream.FlushAsync();

                context.HandleRequest();
            }
        }
    }
}
