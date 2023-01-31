/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using Microsoft.Extensions.Primitives;
using OpenIddict.Extensions;

namespace OpenIddict.Client.Windows;

public static partial class OpenIddictClientWindowsHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create(
            /*
             * Authorization request processing:
             */
            LaunchSystemBrowser.Descriptor,

            /*
             * Redirection request extraction:
             */
            ExtractRequestUriParameters<ExtractRedirectionRequestContext>.Descriptor,

            /*
             * Redirection request handling:
             */
            ProcessResponse<HandleRedirectionRequestContext>.Descriptor,

            /*
             * Redirection response handling:
             */
            ProcessResponse<ApplyRedirectionResponseContext>.Descriptor);

        /// <summary>
        /// Contains the logic responsible for initiating authorization requests using the system browser.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by Windows.
        /// </summary>
        public class LaunchSystemBrowser : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .AddFilter<RequireInteractiveSession>()
                    .UseSingletonHandler<LaunchSystemBrowser>()
                    .SetOrder(50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the OpenIddict Windows integration is designed to work as a universal Windows package.
                // As such, multiple types of application models must be supported to cover most scenarios. E.g:
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

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                var uri = OpenIddictHelpers.AddQueryStringParameters(
                    uri: new Uri(context.AuthorizationEndpoint, UriKind.Absolute),
                    parameters: context.Transaction.Request.GetParameters().ToDictionary(
                        parameter => parameter.Key,
                        parameter => new StringValues((string?[]?) parameter.Value)));

#if SUPPORTS_WINDOWS_RUNTIME
                // While Process.Start()/ShellExecuteEx() can typically be used without any particular restriction
                // by non-sandboxed desktop applications to launch the default system browser, calling these
                // APIs in sandboxed applications will result in an UnauthorizedAccessException being thrown.
                //
                // To avoid that, the OpenIddict host needs to determine whether the platform supports Windows
                // Runtime APIs and favor the Launcher.LaunchUriAsync() API when it's offered by the platform.

                if (OpenIddictClientWindowsHelpers.IsWindowsRuntimeSupported() && await
                    OpenIddictClientWindowsHelpers.TryLaunchBrowserWithWindowsRuntimeAsync(uri))
                {
                    return;
                }
#endif
                if (await OpenIddictClientWindowsHelpers.TryLaunchBrowserWithShellExecuteAsync(uri))
                {
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0385));
            }
        }
    }
}
