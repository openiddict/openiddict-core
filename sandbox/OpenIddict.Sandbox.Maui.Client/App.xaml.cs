#if IOS || MACCATALYST || WINDOWS
namespace OpenIddict.Sandbox.Maui.Client;

public partial class App : Application
{
    public App() => InitializeComponent();

    protected override Window CreateWindow(IActivationState? activationState) => new(new AppShell());
}
#endif
