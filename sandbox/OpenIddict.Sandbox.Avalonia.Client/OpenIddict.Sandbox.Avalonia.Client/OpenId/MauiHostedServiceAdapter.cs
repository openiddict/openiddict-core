//#if IOS || MACCATALYST || WINDOWS
using Microsoft.Extensions.Hosting;
using Microsoft.Maui.Hosting;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace OpenIddict.Sandbox.Maui.Client;

public class MauiHostedServiceAdapter : IMauiInitializeService
{
    private readonly IHostedService _service;

    public MauiHostedServiceAdapter(IHostedService service)
        => _service = service ?? throw new ArgumentNullException(nameof(service));

    public void Initialize(IServiceProvider services)
        => Task.Run(() => _service.StartAsync(CancellationToken.None)).GetAwaiter().GetResult();
}
//#endif
