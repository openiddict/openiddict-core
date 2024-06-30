#if IOS || MACCATALYST || WINDOWS
using Microsoft.Extensions.Hosting;

namespace OpenIddict.Sandbox.Maui.Client;

public class MauiHostApplicationLifetime : IHostApplicationLifetime
{
    private readonly CancellationTokenSource _source = new();

    public CancellationToken ApplicationStarted => new(canceled: true);

    public CancellationToken ApplicationStopping => _source.Token;

    public CancellationToken ApplicationStopped => _source.Token;

    public void StopApplication()
    {
        _source.Cancel(throwOnFirstException: false);
        Environment.Exit(0);
    }
}
#endif
