using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace OpenIddict {
    public interface IOpenIddictStore<TUser, TApplication, TScope> : IUserStore<TUser> where TUser : class where TApplication : class where TScope : class {
        Task<TApplication> FindApplicationByIdAsync(string identifier, CancellationToken cancellationToken);
        Task<TApplication> FindApplicationByLogoutRedirectUri(string url, CancellationToken cancellationToken);
        Task<string> GetApplicationTypeAsync(TApplication application, CancellationToken cancellationToken);
        Task<string> GetDisplayNameAsync(TApplication application, CancellationToken cancellationToken);
        Task<string> GetRedirectUriAsync(TApplication application, CancellationToken cancellationToken);
        Task<bool> ValidateSecretAsync(TApplication application, string secret, CancellationToken cancellationToken);
        Task<IEnumerable<TScope>> GetScopesByApplicationAsync(TApplication application, CancellationToken cancellationToken);
        Task<IEnumerable<TScope>> GetAuthorizationRequesteScopesAsync(IEnumerable<string> requestScopes, CancellationToken cancellationToken);
        Task<string> GetScopeDisplayNameAsync(TScope scope, CancellationToken cancellationToken);
        Task<string> GetScopeDescriptionAsync(TScope scope, CancellationToken cancellationToken);
        Task<string> GetScopeIdAsync(TScope scope, CancellationToken cancellationToken);
    }
}