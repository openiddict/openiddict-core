namespace OpenIddict.Sandbox.AspNetCore.Server.Services;

public interface IEmailSender
{
    Task SendEmailAsync(string email, string subject, string message);
}
