using System.Threading.Tasks;

namespace Mvc.Server.Services {
    public interface IEmailSender {
        Task SendEmailAsync(string email, string subject, string message);
    }
}
