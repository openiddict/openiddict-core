namespace OpenIddict.Sandbox.AspNetCore.Server.Services;

public interface ISmsSender
{
    Task SendSmsAsync(string number, string message);
}
