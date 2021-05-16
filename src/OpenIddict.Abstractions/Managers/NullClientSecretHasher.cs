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
    /// Implements the <see cref="IOpenIddictClientSecretHasher"/> with a null implementation tht does not hash the secret.
    /// </summary>
    /// <remarks>
    /// Only use this class for custom implementations of the <see cref="IOpenIddictApplicationStore{TApplication}"/> interface when your secret is already hashed.
    /// </remarks>
    public class NullClientSecretHasher : IOpenIddictClientSecretHasher
    {
        /// <inheritdoc />
        public ValueTask<string> ObfuscateClientSecretAsync(string secret, CancellationToken cancellationToken = default)
        {
            return new ValueTask<string>(secret);
        }

        /// <inheritdoc />
        public ValueTask<bool> ValidateClientSecretAsync(string secret, string comparand, CancellationToken cancellationToken = default)
        {
            var equals = string.Equals(secret, comparand);

            return new ValueTask<bool>(equals);
        }
    }
}
