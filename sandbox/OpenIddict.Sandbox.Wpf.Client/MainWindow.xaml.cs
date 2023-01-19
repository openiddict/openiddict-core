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

        private async void TwitterLoginButton_Click(object sender, RoutedEventArgs e)
            => await AuthenticateAsync(Providers.Twitter);

        private async Task AuthenticateAsync(string provider)
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the challenge and launch the system browser
                // to allow the user to complete the interactive authentication dance.
                var nonce = await _service.ChallengeWithBrowserAsync(
                    provider, cancellationToken: source.Token);

                // Wait until the user approved or rejected the authorization
                // demand and retrieve the resulting claims-based principal.
                var (_, _, principal) = await _service.AuthenticateWithBrowserAsync(
                    nonce, cancellationToken: source.Token);

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
