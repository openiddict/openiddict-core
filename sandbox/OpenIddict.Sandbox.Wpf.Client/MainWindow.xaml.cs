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
        => await AuthenticateAsync("Local");

    private async void LocalLoginWithGitHubButton_Click(object sender, RoutedEventArgs e)
        => await AuthenticateAsync("Local", new()
        {
            [Parameters.IdentityProvider] = Providers.GitHub
        });

    private async void GitHubLoginButton_Click(object sender, RoutedEventArgs e)
        => await AuthenticateAsync(Providers.GitHub);

    private async Task AuthenticateAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the login buttons to prevent concurrent authentication operations.
        LocalLogin.IsEnabled = false;
        LocalLoginWithGitHub.IsEnabled = false;
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

                // Wait for the user to complete the authorization process.
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
            // Re-enable the login buttons to allow starting a new authentication operation.
            LocalLogin.IsEnabled = true;
            LocalLoginWithGitHub.IsEnabled = true;
            GitHubLogin.IsEnabled = true;
        }
    }
}
