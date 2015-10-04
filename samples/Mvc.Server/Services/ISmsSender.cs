using System.Threading.Tasks;

namespace Mvc.Server.Services {
    public interface ISmsSender {
        Task SendSmsAsync(string number, string message);
    }
}
