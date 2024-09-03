using System.Windows;
using Dapplo.Microsoft.Extensions.Hosting.Wpf;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Sandbox.Wpf.Client;

public partial class MainWindow : Window, IWpfShell
{
    private readonly OpenIddictClientService _service;

    public MainWindow(OpenIddictClientService service)
    {
        _service = service ?? throw new ArgumentNullException(nameof(service));

        InitializeComponent();
    }

    private async void LocalLoginButton_Click(object sender, RoutedEventArgs e)
        => await LogInAsync("Local");

    private async void LocalLoginWithGitHubButton_Click(object sender, RoutedEventArgs e)
        => await LogInAsync("Local", new()
        {
            [Parameters.IdentityProvider] = Providers.GitHub
        });
    private async void LocalLogoutButton_Click(object sender, RoutedEventArgs e)
        => await LogOutAsync("Local");

    private async void GitHubLoginButton_Click(object sender, RoutedEventArgs e)
        => await LogInAsync(Providers.GitHub);

    private async Task LogInAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        LocalLogin.IsEnabled = false;
        LocalLoginWithGitHub.IsEnabled = false;
        LocalLogout.IsEnabled = false;
        GitHubLogin.IsEnabled = false;

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

                // Wait for the user to complete the authorization process and authenticate the callback request,
                // which allows resolving all the claims contained in the merged principal created by OpenIddict.
                var principal = (await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = source.Token,
                    Nonce = result.Nonce
                })).Principal;

                MessageBox.Show($"Welcome, {principal.FindFirst(Claims.Name)!.Value}.",
                    "Authentication successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            catch (OperationCanceledException)
            {
                MessageBox.Show("The authentication process was aborted.",
                    "Authentication timed out", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                MessageBox.Show("The authorization was denied by the end user.",
                    "Authorization denied", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            catch
            {
                MessageBox.Show("An error occurred while trying to authenticate the user.",
                    "Authentication failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            LocalLogin.IsEnabled = true;
            LocalLoginWithGitHub.IsEnabled = true;
            LocalLogout.IsEnabled = true;
            GitHubLogin.IsEnabled = true;
        }
    }

    private async Task LogOutAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        LocalLogin.IsEnabled = false;
        LocalLoginWithGitHub.IsEnabled = false;
        LocalLogout.IsEnabled = false;
        GitHubLogin.IsEnabled = false;

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

                MessageBox.Show($"The user was successfully logged out from the local server.",
                    "Logout demand successful", MessageBoxButton.OK, MessageBoxImage.Information);
            }

            catch (OperationCanceledException)
            {
                MessageBox.Show("The logout process was aborted.",
                    "Logout timed out", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            catch
            {
                MessageBox.Show("An error occurred while trying to log the user out.",
                    "Logout failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            LocalLogin.IsEnabled = true;
            LocalLoginWithGitHub.IsEnabled = true;
            LocalLogout.IsEnabled = true;
            GitHubLogin.IsEnabled = true;
        }
    }
}
