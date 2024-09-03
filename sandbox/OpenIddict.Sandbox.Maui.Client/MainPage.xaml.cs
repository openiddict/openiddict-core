#if IOS || MACCATALYST || WINDOWS
using OpenIddict.Abstractions;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Sandbox.Maui.Client;

public partial class MainPage : ContentPage
{
    private readonly OpenIddictClientService _service;

    public MainPage(OpenIddictClientService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));

        InitializeComponent();
    }

    private async void OnLocalLoginButtonClicked(object sender, EventArgs e)
        => await LogInAsync("Local");

    private async void OnLocalLoginWithGitHubButtonClicked(object sender, EventArgs e)
        => await LogInAsync("Local", new()
        {
            [Parameters.IdentityProvider] = Providers.GitHub
        });

    private async void OnLocalLogoutButtonClicked(object sender, EventArgs e)
        => await LogOutAsync("Local");

    private async void OnTwitterLoginButtonClicked(object sender, EventArgs e)
        => await LogInAsync(Providers.Twitter);

    private async Task LogInAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        LocalLogin.IsEnabled = false;
        LocalLoginWithGitHub.IsEnabled = false;
        LocalLogout.IsEnabled = false;
        TwitterLogin.IsEnabled = false;

        try
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the authentication flow (typically, by starting the system browser).
                var result = await _service.ChallengeInteractivelyAsync(new()
                {
                    AdditionalAuthorizationRequestParameters = parameters,
                    CancellationToken = source.Token,
                    ProviderName = provider
                });

                // Wait for the user to complete the authorization process.
                var principal = (await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = source.Token,
                    Nonce = result.Nonce
                })).Principal;

                Message.Text = $"Welcome, {principal.FindFirst(Claims.Name)!.Value}.";
            }

            catch (OperationCanceledException)
            {
                Message.Text = "The authentication process was aborted.";
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                Message.Text = "The authorization was denied by the end user.";
            }

            catch
            {
                Message.Text = "An error occurred while trying to authenticate the user.";
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            LocalLogin.IsEnabled = true;
            LocalLoginWithGitHub.IsEnabled = true;
            LocalLogout.IsEnabled = true;
            TwitterLogin.IsEnabled = true;
        }
    }

    private async Task LogOutAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        LocalLogin.IsEnabled = false;
        LocalLoginWithGitHub.IsEnabled = false;
        LocalLogout.IsEnabled = false;
        TwitterLogin.IsEnabled = false;

        try
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the logout flow (typically, by starting the system browser).
                var result = await _service.SignOutInteractivelyAsync(new()
                {
                    AdditionalEndSessionRequestParameters = parameters,
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

                Message.Text = "The user was successfully logged out from the local server.";
            }

            catch (OperationCanceledException)
            {
                Message.Text = "The logout process was aborted.";
            }

            catch
            {
                Message.Text = "An error occurred while trying to log the user out.";
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            LocalLogin.IsEnabled = true;
            LocalLoginWithGitHub.IsEnabled = true;
            LocalLogout.IsEnabled = true;
            TwitterLogin.IsEnabled = true;
        }
    }
}
#endif
