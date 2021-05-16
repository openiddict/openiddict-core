/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading;
using System.Threading.Tasks;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Hashs and compares client secrets.
    /// </summary>
    public interface IOpenIddictClientSecretHasher
    {
        /// <summary>
        /// Validates the specified value to ensure it corresponds to the client secret.
        /// Note: when overriding this method, using a time-constant comparer is strongly recommended.
        /// </summary>
        /// <param name="secret">The client secret to compare to the value stored in the database.</param>
        /// <param name="comparand">The value stored in the database, which is usually a hashed representation of the secret.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation,
        /// whose result returns a boolean indicating whether the specified value was valid.
        /// </returns>
        ValueTask<bool> ValidateClientSecretAsync(string secret, string comparand, CancellationToken cancellationToken = default);

        /// <summary>
        /// Obfuscates the specified client secret so it can be safely stored in a database.
        /// By default, this method returns a complex hashed representation computed using PBKDF2.
        /// </summary>
        /// <param name="secret">The client secret.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>
        /// A <see cref="ValueTask"/> that can be used to monitor the asynchronous operation.
        /// </returns>
        ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default);
    }
}
