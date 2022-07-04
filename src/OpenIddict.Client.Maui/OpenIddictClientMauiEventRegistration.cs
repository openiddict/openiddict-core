/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.Maui.LifecycleEvents;

#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
using Microsoft.Windows.AppLifecycle;
using Windows.ApplicationModel.Activation;
#endif

namespace OpenIddict.Client.Maui;

/// <summary>
/// Contains the logic necessary to register the event handlers
/// required by the OpenIddict client to process responses.
/// </summary>
public class OpenIddictClientMauiEventRegistration : LifecycleEventRegistration
{
    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientMauiEventRegistration"/> class.
    /// </summary>
    public OpenIddictClientMauiEventRegistration()
        : base(Configure)
    {
    }

    /// <summary>
    /// Registers the event handlers required by the OpenIddict client to process responses.
    /// </summary>
    /// <param name="builder">The MAUI lifecycle builder.</param>
    private static void Configure(ILifecycleBuilder builder)
    {
#if SUPPORTS_WINDOWS_APPLICATION_LIFECYCLE
        builder.AddWindows(builder => builder.OnLaunching((sender, args) =>
        {
            // Warning: this delegate CANNOT be async to ensure ManualResetEventSlim
            // can block the initialization of the current instance, if necessary.

            var instance = AppInstance.GetCurrent();

            // Register an event handler that will handle the activation events sent by
            // other instances redirecting authorization responses that include a state
            // token created by a different application instance. Note: this handler is
            // only invoked for future activations, not the initial application launch.
            instance.Activated += async (sender, args) =>
            {
                if (args.Data is IProtocolActivatedEventArgs arguments)
                {
                    await OnActivatedAsync(arguments, MauiWinUIApplication.Current.Services, barrier: null);
                }

                // Ignore other types of redirected instance activations.
            };

            // If the current instance was launched via a protocol activation, trigger
            // the ProcessRequestContext event to give OpenIddict a chance to handle
            // the authorization response if the URI is one of the addresses configured
            // for the redirection endpoint in the OpenIddict client options.
            if (instance.GetActivatedEventArgs()?.Data is IProtocolActivatedEventArgs arguments)
            {
                // If more than one instances of the application already exist, block
                // the initialization of the current instance using a manual-reset event
                // to prevent the main window from being created, which allows processing
                // the authorization response without disturbing users with flashing windows.
                if (AppInstance.GetInstances() is { Count: > 1 })
                {
                    using var barrier = new ManualResetEventSlim(initialState: false);
                    _ = OnActivatedAsync(arguments, ((MauiWinUIApplication) sender).Services, barrier);
                    barrier.Wait();

                    return;
                }

                _ = OnActivatedAsync(arguments, ((MauiWinUIApplication) sender).Services, barrier: null);
            }

            static async Task OnActivatedAsync(IProtocolActivatedEventArgs arguments,
                IServiceProvider provider, ManualResetEventSlim? barrier)
            {
                try
                {
                    var dispatcher = provider.GetRequiredService<IOpenIddictClientDispatcher>();
                    var factory = provider.GetRequiredService<IOpenIddictClientFactory>();

                    // Create a client transaction and store the protocol activation event arguments so they
                    // can be retrieved by the MAUI-specific client event handlers that need to access them.
                    var transaction = await factory.CreateTransactionAsync();
                    transaction.SetProperty(typeof(IProtocolActivatedEventArgs).FullName!, arguments);

                    var context = new ProcessRequestContext(transaction);
                    await dispatcher.DispatchAsync(context);

                    if (context.IsRejected)
                    {
                        await dispatcher.DispatchAsync(new ProcessErrorContext(transaction)
                        {
                            Error = context.Error ?? Errors.InvalidRequest,
                            ErrorDescription = context.ErrorDescription,
                            ErrorUri = context.ErrorUri,
                            Response = new OpenIddictResponse()
                        });
                    }
                }

                finally
                {
                    barrier?.Set();
                }
            }
        }));
#endif
    }
}
