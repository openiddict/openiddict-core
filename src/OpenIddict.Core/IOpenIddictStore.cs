using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace OpenIddict {
    public interface IOpenIddictStore<TUser, TApplication> : IUserStore<TUser> where TUser : class where TApplication : class {
        Task<TApplication> FindApplicationByIdAsync(string identifier, CancellationToken cancellationToken);
        Task<TApplication> FindApplicationByLogoutRedirectUri(string url, CancellationToken cancellationToken);
        Task<string> GetApplicationTypeAsync(TApplication application, CancellationToken cancellationToken);
        Task<string> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken);
        Task<string> GetRedirectUriAsync(TApplication application, CancellationToken cancellationToken);
        Task<string> GetHashedSecretAsync(TApplication application, CancellationToken cancellationToken);
    }
}