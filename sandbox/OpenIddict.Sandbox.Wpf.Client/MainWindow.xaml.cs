using System.Windows;
using Dapplo.Microsoft.Extensions.Hosting.Wpf;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Sandbox.Wpf.Client
{
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

        private async void GitHubLoginButton_Click(object sender, RoutedEventArgs e)
            => await AuthenticateAsync(Providers.GitHub);

        private async Task AuthenticateAsync(string provider)
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the authentication flow (typically, by
                // starting the system browser) and wait for the user to complete it.
                var (_, _, principal) = await _service.AuthenticateInteractivelyAsync(
                    provider, cancellationToken: source.Token);

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
    }
}
