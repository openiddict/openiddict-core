#if IOS || MACCATALYST || WINDOWS
namespace OpenIddict.Sandbox.Maui.Client;

public partial class AppShell : Shell
{
    public AppShell() => InitializeComponent();
}
#endif
