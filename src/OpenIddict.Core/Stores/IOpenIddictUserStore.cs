/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace OpenIddict {
    /// <summary>
    /// Provides methods allowing to manage the users stored in a database.
    /// </summary>
    /// <typeparam name="TUser">The type of the User entity.</typeparam>
    public interface IOpenIddictUserStore<TUser> : IUserStore<TUser> where TUser : class {
        /// <summary>
        /// Creates a new token associated with the given user.
        /// </summary>
        /// <param name="user">The user associated with the token.</param>
        /// <param name="type">The token type.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        Task<string> CreateTokenAsync(TUser user, string type, CancellationToken cancellationToken);

        /// <summary>
        /// Creates a new token associated with the given user and
        /// attached to the tokens issued to the specified client.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="client">The application.</param>
        /// <param name="type">The token type.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the unique identifier associated with the token.
        /// </returns>
        Task<string> CreateTokenAsync(TUser user, string client, string type, CancellationToken cancellationToken);

        /// <summary>
        /// Retrieves the token identifiers associated with a user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="Task"/> that can be used to monitor the asynchronous operation,
        /// whose result returns the tokens associated with the user.
        /// </returns>
        Task<IEnumerable<string>> GetTokensAsync(TUser user, CancellationToken cancellationToken);
    }
}