using Avalonia.Controls;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Sandbox.Avalonia.Client.ViewModels;

public class MainViewModel : ViewModelBase
{
#pragma warning disable CA1822 // Mark members as static
    public string Greeting => "Welcome to Avalonia!";

    private OpenIddictClientService _service;

    public ReactiveCommand<Unit,Unit> LoginCommand { get; }
    public ReactiveCommand<Unit, Unit> LoginWithGithubCommand { get; }
    public ReactiveCommand<Unit, Unit> LogoutCommand { get; }
    public ReactiveCommand<Unit, Unit> CancelCommand { get; }
#pragma warning restore CA1822 // Mark members as static

    public MainViewModel(OpenIddictClientService service)
	{
        _service = service;

        var canExecute = this.WhenAnyValue(v => v.IsEnabled);

        LoginCommand = ReactiveCommand.CreateFromTask(LoginAsync, canExecute);
        LoginWithGithubCommand = ReactiveCommand.CreateFromTask(LoginWithGithubAsync, canExecute);
        LogoutCommand = ReactiveCommand.CreateFromTask(LogoutAsync, canExecute);
        CancelCommand = ReactiveCommand.CreateFromTask(CancelAsync, canExecute.Select(v => !v));

        Message = "Welcome to Avalonia UI";
    }

    private string _message;
    private bool _isEnabled = true;

    public string Message 
    {
        get { return _message; }
        set { this.RaiseAndSetIfChanged(ref _message, value); }
    }

    public bool IsEnabled
    {
        get { return _isEnabled; }
        set { this.RaiseAndSetIfChanged(ref _isEnabled, value); }
    }

    private async Task LoginAsync()
	{
        await LogInAsync("Local");
    }
    private async Task LoginWithGithubAsync()
    {
        await LogInAsync("Local", new()
        {
            [Parameters.IdentityProvider] = "GitHub"
        });
    }
    private async Task LogoutAsync()
    {
        await LogOutAsync("Local");
    }

    CancellationTokenSource _source;

    private async Task CancelAsync()
    {

        if (IsEnabled)
            return;

        if (_source is null)
            return;

        _source.Cancel();
    }



    private async Task LogInAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        IsEnabled = false;

        try
        {
            _source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the authentication flow (typically, by starting the system browser).
                var result = await _service.ChallengeInteractivelyAsync(new()
                {
                    AdditionalAuthorizationRequestParameters = parameters,
                    CancellationToken = _source.Token,
                    ProviderName = provider
                });

                // Wait for the user to complete the authorization process.
                var principal = (await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = _source.Token,
                    Nonce = result.Nonce
                })).Principal;

                Message= $"Welcome, {principal.FindFirst(Claims.Name)!.Value}.";
            }

            catch (OperationCanceledException)
            {
                Message= "The authentication process was aborted.";
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                Message= "The authorization was denied by the end user.";
            }

            catch
            {
                Message = "An error occurred while trying to authenticate the user.";
            }
        }

        finally
        {
            _source.Dispose();
            // Re-enable the buttons to allow starting a new operation.
            IsEnabled = true;
        }
    }

    private async Task LogOutAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        IsEnabled = false;

        try
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the logout flow (typically, by starting the system browser).
                var result = await _service.SignOutInteractivelyAsync(new()
                {
                    AdditionalLogoutRequestParameters = parameters,
                    CancellationToken = source.Token,
                    ProviderName = provider
                });

                // Wait for the user to complete the logout process and authenticate the callback request.
                //
                // Note: in this case, only the claims contained in the state token can be resolved since
                // the authorization server doesn't return any other user identity during a logout dance.
                await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = source.Token,
                    Nonce = result.Nonce
                });

                Message = "The user was successfully logged out from the local server.";
            }

            catch (OperationCanceledException)
            {
                Message = "The logout process was aborted.";
            }

            catch
            {
                Message = "An error occurred while trying to log the user out.";
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            IsEnabled = true;
        }
    }
}
