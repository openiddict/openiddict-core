/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;

#if SUPPORTS_ANDROID
using Android.Content;
using NativeUri = Android.Net.Uri;
#endif

#if SUPPORTS_ANDROID && SUPPORTS_ANDROIDX_BROWSER
using AndroidX.Browser.CustomTabs;
#endif

#if SUPPORTS_AUTHENTICATION_SERVICES
using AuthenticationServices;
#endif

#if SUPPORTS_APPKIT
using NativeWindow = AppKit.NSWindow;
#elif SUPPORTS_UIKIT
using NativeWindow = UIKit.UIWindow;
#endif

#if SUPPORTS_WINDOWS_RUNTIME
using Windows.Security.Authentication.Web;
using Windows.UI.Core;
#endif

namespace OpenIddict.Client.SystemIntegration;

public static partial class OpenIddictClientSystemIntegrationHandlers
{
    public static class Session
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * End session request processing:
             */
            StartASWebAuthenticationSession.Descriptor,
            LaunchCustomTabsIntent.Descriptor,
            InvokeWebAuthenticationBroker.Descriptor,
            LaunchSystemBrowser.Descriptor,

            /*
             * Post-logout redirection request extraction:
             */
            ExtractGetOrPostHttpListenerRequest<ExtractPostLogoutRedirectionRequestContext>.Descriptor,
            ExtractProtocolActivationParameters<ExtractPostLogoutRedirectionRequestContext>.Descriptor,
            ExtractPlatformCallbackParameters<ExtractPostLogoutRedirectionRequestContext>.Descriptor,

            /*
             * Post-logout redirection response handling:
             */
            AttachHttpResponseCode<ApplyPostLogoutRedirectionResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyPostLogoutRedirectionResponseContext>.Descriptor,
            ProcessEmptyHttpResponse.Descriptor,
            ProcessProtocolActivationResponse<ApplyPostLogoutRedirectionResponseContext>.Descriptor,
            ProcessPlatformCallbackResponse<ApplyPostLogoutRedirectionResponseContext>.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for initiating end session requests using an AS web authentication session.
        /// Note: this handler is not used when the user session is not interactive.
        /// </summary>
        public class StartASWebAuthenticationSession : IOpenIddictClientHandler<ApplyEndSessionRequestContext>
        {
            private readonly OpenIddictClientSystemIntegrationService _service;

            public StartASWebAuthenticationSession(OpenIddictClientSystemIntegrationService service)
                => _service = service ?? throw new ArgumentNullException(nameof(service));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyEndSessionRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .AddFilter<RequireASWebAuthenticationSession>()
                    .UseSingletonHandler<StartASWebAuthenticationSession>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            [SupportedOSPlatform("ios12.0")]
            [SupportedOSPlatform("maccatalyst13.1")]
            [SupportedOSPlatform("macos10.15")]
#pragma warning disable CS1998
            public async ValueTask HandleAsync(ApplyEndSessionRequestContext context)
#pragma warning restore CS1998
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

#if SUPPORTS_AUTHENTICATION_SERVICES && SUPPORTS_FOUNDATION
                if (string.IsNullOrEmpty(context.PostLogoutRedirectUri) ||
                    !Uri.TryCreate(context.PostLogoutRedirectUri, UriKind.Absolute, out Uri? uri))
                {
                    return;
                }

                if (!IsASWebAuthenticationSessionSupported())
                {
                    throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0446));
                }

                var source = new TaskCompletionSource<OpenIddictClientSystemIntegrationPlatformCallback>(
                    TaskCreationOptions.RunContinuationsAsynchronously);

                // OpenIddict represents the complete interactive end session dance as a two-phase process:
                //   - The sign-out, during which the user is redirected to the authorization server, either
                //     by launching the system browser or, as in this case, using a web-view-like approach.
                //
                //   - The callback validation that takes place after the authorization server and the user approved
                //     the demand and redirected the user agent to the client (using either protocol activation,
                //     an embedded web server or by tracking the return URL of the web view created for the process).
                //
                // Unlike OpenIddict, ASWebAuthenticationSession materializes this process as a single/one-shot API
                // that opens the system-managed authentication host, navigates to the specified request URI and
                // doesn't return until the specified callback URI is reached or the modal closed by the user.
                // To accomodate OpenIddict's model, successful results are processed as any other callback request.

                using var session = CreateASWebAuthenticationSession();

#if SUPPORTS_PRESENTATION_CONTEXT_PROVIDER
                // On iOS 13.0 and higher, a presentation context provider returning the UI window to
                // which the Safari web view will be attached MUST be provided (otherwise, a code 2
                // error is returned by ASWebAuthenticationSession). To avoid that, a default provider
                // pointing to the current UI window is automatically attached on iOS 13.0 and higher.
                if (OperatingSystem.IsIOSVersionAtLeast(13))
                {
#pragma warning disable CA1416
                    session.PresentationContextProvider = new ASWebAuthenticationPresentationContext(
                        GetCurrentUIWindow() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0447)));
#pragma warning restore CA1416
                }
#endif
                using var registration = context.CancellationToken.Register(
                    static state => ((ASWebAuthenticationSession) state!).Cancel(), session);

                if (!session.Start())
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0448));
                }

                OpenIddictClientSystemIntegrationPlatformCallback callback;

                try
                {
                    callback = await source.Task.WaitAsync(context.CancellationToken);
                }

                // Since the result of this operation is known by the time the task signaled by ASWebAuthenticationSession
                // returns, canceled demands can directly be handled and surfaced here, as part of the challenge handling.

                catch (NSErrorException exception) when (exception.Error is {
                    Domain: "com.apple.AuthenticationServices.WebAuthenticationSession",
                    Code  : (int) ASWebAuthenticationSessionErrorCode.CanceledLogin })
                {
                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2149),
                        uri: SR.FormatID8000(SR.ID2149));

                    return;
                }

                catch (NSErrorException exception)
                {
                    context.Logger.LogError(exception, SR.GetResourceString(SR.ID6232));

                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2136),
                        uri: SR.FormatID8000(SR.ID2136));

                    return;
                }

                await _service.HandlePlatformCallbackAsync(callback, context.CancellationToken);
                context.HandleRequest();
                return;

                ASWebAuthenticationSession CreateASWebAuthenticationSession()
                {
                    // Starting with iOS 17.4+, Mac Catalyst 17.4+ and macOS 14.4+, the ASWebAuthenticationSession initializer
                    // accepting a custom scheme string is now deprecated and is replaced by an initializer taking an
                    // ASWebAuthenticationSessionCallback object, which allows supporting HTTPS callback URIs/Universal Links.
                    if (OperatingSystem.IsIOSVersionAtLeast(17, 4) ||
                        OperatingSystem.IsMacCatalystVersionAtLeast(17, 4) ||
                        OperatingSystem.IsMacOSVersionAtLeast(14, 4))
                    {
                        return new ASWebAuthenticationSession(
                            url: CreateUrl(),
                            callback: uri switch
                            {
                                // Note: non-default ports are not allowed in associated domains, that are
                                // required to use HTTPS URIs with the ASWebAuthenticationSessionCallback API.
                                Uri { IsDefaultPort: true } uri when string.Equals(
                                    uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                                    => ASWebAuthenticationSessionCallback.Create(
                                        httpsHost: uri.Host,
                                        path     : uri.AbsolutePath is ['/', _, ..] ? uri.AbsolutePath[1..] : uri.AbsoluteUri),

                                Uri uri when !string.Equals(uri.Scheme, Uri.UriSchemeHttp,  StringComparison.OrdinalIgnoreCase) &&
                                             !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                                    => ASWebAuthenticationSessionCallback.Create(uri.Scheme),

                                // HTTP-only callback URIs and HTTPS URIs using non-default ports
                                // are not supported by the ASWebAuthenticationSessionCallback API.
                                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0450))
                            },
                            completionHandler: HandleCallback);
                    }

                    // On older platforms, only callback URIs using a custom scheme can be used.
                    if (string.Equals(uri.Scheme, Uri.UriSchemeHttp,  StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0450));
                    }

                    return new ASWebAuthenticationSession(CreateUrl(), uri.Scheme, HandleCallback);

                    NSUrl CreateUrl() => new(OpenIddictHelpers.AddQueryStringParameters(
                        uri: new Uri(context.EndSessionEndpoint, UriKind.Absolute),
                        parameters: context.Transaction.Request.GetParameters().ToDictionary(
                            parameter => parameter.Key,
                            parameter => new StringValues((string?[]?) parameter.Value))).AbsoluteUri);

                    void HandleCallback(NSUrl? url, NSError? error)
                    {
                        if (url is not null)
                        {
                            var parameters = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

                            if (!string.IsNullOrEmpty(url.Query))
                            {
                                foreach (var parameter in OpenIddictHelpers.ParseQuery(url.Query))
                                {
                                    parameters[parameter.Key] = parameter.Value.Count switch
                                    {
                                        0 => default,
                                        1 => parameter.Value[0],
                                        _ => parameter.Value.ToArray()
                                    };
                                }
                            }

                            // Note: the fragment is always processed after the query string to ensure that
                            // parameters extracted from the fragment are preferred to parameters extracted
                            // from the query string when they are present in both parts.

                            if (!string.IsNullOrEmpty(url.Fragment))
                            {
                                foreach (var parameter in OpenIddictHelpers.ParseFragment(url.Fragment))
                                {
                                    parameters[parameter.Key] = parameter.Value.Count switch
                                    {
                                        0 => default,
                                        1 => parameter.Value[0],
                                        _ => parameter.Value.ToArray()
                                    };
                                }
                            }

                            source.SetResult(new OpenIddictClientSystemIntegrationPlatformCallback(url!, parameters)
                            {
                                // Attach the raw URL to the callback properties.
                                Properties = { [typeof(NSUrl).FullName!] = url }
                            });
                        }

                        else if (error is not null)
                        {
                            source.SetException(new NSErrorException(error));
                        }

                        else
                        {
                            source.SetException(new InvalidOperationException(SR.GetResourceString(SR.ID0448)));
                        }
                    }
                }
#else
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0446));
#endif
            }

#if SUPPORTS_AUTHENTICATION_SERVICES
            class ASWebAuthenticationPresentationContext(NativeWindow window) : NSObject,
                IASWebAuthenticationPresentationContextProviding
            {
                NativeWindow IASWebAuthenticationPresentationContextProviding.GetPresentationAnchor(
                    ASWebAuthenticationSession session) => window;
            }
#endif
        }

        /// <summary>
        /// Contains the logic responsible for initiating end session requests using a custom tabs intent.
        /// Note: this handler is not used when the user session is not interactive.
        /// </summary>
        public class LaunchCustomTabsIntent : IOpenIddictClientHandler<ApplyEndSessionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyEndSessionRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .AddFilter<RequireCustomTabsIntent>()
                    .UseSingletonHandler<LaunchCustomTabsIntent>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            [SupportedOSPlatform("android21.0")]
#pragma warning disable CS1998
            public async ValueTask HandleAsync(ApplyEndSessionRequestContext context)
#pragma warning restore CS1998
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

#if SUPPORTS_ANDROID && SUPPORTS_ANDROIDX_BROWSER
                if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    return;
                }

                if (!IsCustomTabsIntentSupported())
                {
                    throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0452));
                }

                using var builder = new CustomTabsIntent.Builder();
                using var intent = builder.Build();

                // Note: using ActivityFlags.NewTask is required when
                // creating intents without a parent activity attached.
                intent.Intent.AddFlags(ActivityFlags.NewTask);

                // Note: unlike iOS's ASWebAuthenticationSession or UWP's WebAuthenticationBroker,
                // Android's CustomTabsIntent API doesn't support specifying a "target" URI and uses
                // an asynchronous and isolated model that doesn't allow tracking the current URI.
                //
                // As such, the callback request can only be handled at a later stage by creating a
                // custom activity responsible for handling callback URIs pointing to a custom scheme.
                intent.LaunchUrl(Application.Context, NativeUri.Parse(OpenIddictHelpers.AddQueryStringParameters(
                    uri: new Uri(context.EndSessionEndpoint, UriKind.Absolute),
                    parameters: context.Transaction.Request.GetParameters().ToDictionary(
                        parameter => parameter.Key,
                        parameter => new StringValues((string?[]?) parameter.Value))).AbsoluteUri)!);

                context.HandleRequest();
#else
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0452));
#endif
            }
        }

        /// <summary>
        /// Contains the logic responsible for initiating end session requests using the web authentication broker.
        /// Note: this handler is not used when the user session is not interactive.
        /// </summary>
        public class InvokeWebAuthenticationBroker : IOpenIddictClientHandler<ApplyEndSessionRequestContext>
        {
            private readonly OpenIddictClientSystemIntegrationService _service;

            public InvokeWebAuthenticationBroker(OpenIddictClientSystemIntegrationService service)
                => _service = service ?? throw new ArgumentNullException(nameof(service));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyEndSessionRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .AddFilter<RequireWebAuthenticationBroker>()
                    .UseSingletonHandler<InvokeWebAuthenticationBroker>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            [SupportedOSPlatform("windows10.0.17763")]
#pragma warning disable CS1998
            public async ValueTask HandleAsync(ApplyEndSessionRequestContext context)
#pragma warning restore CS1998
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

#if SUPPORTS_WINDOWS_RUNTIME
                if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    return;
                }

                // Note: WebAuthenticationBroker internally requires a pointer to the CoreWindow object associated
                // to the thread from which the challenge operation is started. Unfortunately, CoreWindow - and by
                // extension WebAuthenticationBroker - are only supported on UWP and cannot be used in Win32 apps.
                //
                // To ensure a meaningful exception is returned when the web authentication broker is used with an
                // incompatible application model (e.g WinUI 3.0), the presence of a CoreWindow is verified here.
                //
                // See https://github.com/microsoft/WindowsAppSDK/issues/398 for more information.
                if (!IsWebAuthenticationBrokerSupported() || CoreWindow.GetForCurrentThread() is null)
                {
                    throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0392));
                }

                // OpenIddict represents the complete interactive end session dance as a two-phase process:
                //   - The sign-out, during which the user is redirected to the authorization server, either
                //     by launching the system browser or, as in this case, using a web-view-like approach.
                //
                //   - The callback validation that takes place after the authorization server and the user approved
                //     the demand and redirected the user agent to the client (using either protocol activation,
                //     an embedded web server or by tracking the return URL of the web view created for the process).
                //
                // Unlike OpenIddict, WebAuthenticationBroker materializes this process as a single/one-shot API
                // that opens the system-managed authentication host, navigates to the specified request URI and
                // doesn't return until the specified callback URI is reached or the modal closed by the user.
                // To accomodate OpenIddict's model, successful results are processed as any other callback request.

                // Note: IAsyncOperation<T>.AsTask(context.CancellationToken) is deliberately not used here as
                // the asynchronous operation returned by the web authentication broker is not cancellable.
                switch (await WebAuthenticationBroker.AuthenticateAsync(
                    options    : WebAuthenticationOptions.None,
                    requestUri : OpenIddictHelpers.AddQueryStringParameters(
                        uri: new Uri(context.EndSessionEndpoint, UriKind.Absolute),
                        parameters: context.Transaction.Request.GetParameters().ToDictionary(
                            parameter => parameter.Key,
                            parameter => new StringValues((string?[]?) parameter.Value))),
                    callbackUri: new Uri(context.PostLogoutRedirectUri, UriKind.Absolute)))
                {
                    case { ResponseStatus: WebAuthenticationStatus.Success } result
                        when Uri.TryCreate(result.ResponseData, UriKind.Absolute, out Uri? uri):
                        var parameters = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

                        if (!string.IsNullOrEmpty(uri.Query))
                        {
                            foreach (var parameter in OpenIddictHelpers.ParseQuery(uri.Query))
                            {
                                parameters[parameter.Key] = parameter.Value.Count switch
                                {
                                    0 => default,
                                    1 => parameter.Value[0],
                                    _ => parameter.Value.ToArray()
                                };
                            }
                        }

                        // Note: the fragment is always processed after the query string to ensure that
                        // parameters extracted from the fragment are preferred to parameters extracted
                        // from the query string when they are present in both parts.

                        if (!string.IsNullOrEmpty(uri.Fragment))
                        {
                            foreach (var parameter in OpenIddictHelpers.ParseFragment(uri.Fragment))
                            {
                                parameters[parameter.Key] = parameter.Value.Count switch
                                {
                                    0 => default,
                                    1 => parameter.Value[0],
                                    _ => parameter.Value.ToArray()
                                };
                            }
                        }

                        var callback = new OpenIddictClientSystemIntegrationPlatformCallback(uri, parameters)
                        {
                            // Attach the authentication result to the properties.
                            Properties = { [typeof(WebAuthenticationResult).FullName!] = result }
                        };

                        await _service.HandlePlatformCallbackAsync(callback, context.CancellationToken);
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
#else
                throw new PlatformNotSupportedException(SR.GetResourceString(SR.ID0392));
#endif
            }
        }

        /// <summary>
        /// Contains the logic responsible for initiating end session requests using the system browser.
        /// Note: this handler is not used when the user session is not interactive.
        /// </summary>
        public class LaunchSystemBrowser : IOpenIddictClientHandler<ApplyEndSessionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyEndSessionRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .AddFilter<RequireSystemBrowser>()
                    .UseSingletonHandler<LaunchSystemBrowser>()
                    .SetOrder(InvokeWebAuthenticationBroker.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                var uri = OpenIddictHelpers.AddQueryStringParameters(
                    uri: new Uri(context.EndSessionEndpoint, UriKind.Absolute),
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
                    if (IsUriLauncherSupported() && await TryLaunchBrowserWithWindowsRuntimeAsync(uri))
                    {
                        context.HandleRequest();
                        return;
                    }
#endif
                    if (await TryLaunchBrowserWithShellExecuteAsync(uri))
                    {
                        context.HandleRequest();
                        return;
                    }
                }

#if SUPPORTS_ANDROID
                if (OperatingSystem.IsAndroid() && TryLaunchBrowserWithGenericIntent(uri))
                {
                    context.HandleRequest();
                    return;
                }
#endif

#if SUPPORTS_UIKIT
                if ((OperatingSystem.IsIOS() || OperatingSystem.IsMacCatalyst()) && await TryLaunchBrowserWithUIApplicationAsync(uri))
                {
                    context.HandleRequest();
                    return;
                }
#elif SUPPORTS_APPKIT
                if (OperatingSystem.IsMacOS() && TryLaunchBrowserWithNSWorkspace(uri))
                {
                    context.HandleRequest();
                    return;
                }
#endif
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && await TryLaunchBrowserWithXdgOpenAsync(uri))
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
        public sealed class ProcessEmptyHttpResponse : IOpenIddictClientHandler<ApplyPostLogoutRedirectionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyPostLogoutRedirectionResponseContext>()
                    .AddFilter<RequireHttpListenerContext>()
                    .UseSingletonHandler<ProcessEmptyHttpResponse>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyPostLogoutRedirectionResponseContext context)
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

                // Return a message indicating whether the sign-out process
                // succeeded or failed and that will be visible by the user.
                var buffer = Encoding.UTF8.GetBytes(context.Transaction.Response.Error switch
                {
                    null or { Length: 0 } => "Logout completed. Please return to the application.",
                    Errors.AccessDenied   => "Logout denied. Please return to the application.",
                    _                     => "Logout failed. Please return to the application."
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
