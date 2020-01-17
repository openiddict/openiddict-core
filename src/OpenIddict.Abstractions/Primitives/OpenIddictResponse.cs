/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;

namespace OpenIddict.Abstractions
{
    /// <summary>
    /// Represents a generic OpenIddict response.
    /// </summary>
    /// <remarks>
    /// Security notice: developers instantiating this type are responsible of ensuring that the
    /// imported parameters are safe and won't cause the resulting message to grow abnormally,
    /// which may result in an excessive memory consumption and a potential denial of service.
    /// </remarks>
    [DebuggerDisplay("Parameters: {Parameters.Count}")]
    [JsonConverter(typeof(OpenIddictConverter))]
    public class OpenIddictResponse : OpenIddictMessage
    {
        /// <summary>
        /// Initializes a new OpenIddict response.
        /// </summary>
        public OpenIddictResponse()
            : base() { }

        /// <summary>
        /// Initializes a new OpenIddict response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIddictResponse([NotNull] IEnumerable<KeyValuePair<string, JsonElement>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenIddict response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIddictResponse([NotNull] IEnumerable<KeyValuePair<string, OpenIddictParameter>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenIddict response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIddictResponse([NotNull] IEnumerable<KeyValuePair<string, string>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenIddict response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIddictResponse([NotNull] IEnumerable<KeyValuePair<string, string[]>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Initializes a new OpenIddict response.
        /// </summary>
        /// <param name="parameters">The response parameters.</param>
        public OpenIddictResponse([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters)
            : base(parameters) { }

        /// <summary>
        /// Gets or sets the "access_token" parameter.
        /// </summary>
        public string AccessToken
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.AccessToken);
            set => SetParameter(OpenIddictConstants.Parameters.AccessToken, value);
        }

        /// <summary>
        /// Gets or sets the "code" parameter.
        /// </summary>
        public string Code
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.Code);
            set => SetParameter(OpenIddictConstants.Parameters.Code, value);
        }

        /// <summary>
        /// Gets or sets the "device_code" parameter.
        /// </summary>
        public string DeviceCode
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.DeviceCode);
            set => SetParameter(OpenIddictConstants.Parameters.DeviceCode, value);
        }

        /// <summary>
        /// Gets or sets the "error" parameter.
        /// </summary>
        public string Error
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.Error);
            set => SetParameter(OpenIddictConstants.Parameters.Error, value);
        }

        /// <summary>
        /// Gets or sets the "error_description" parameter.
        /// </summary>
        public string ErrorDescription
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.ErrorDescription);
            set => SetParameter(OpenIddictConstants.Parameters.ErrorDescription, value);
        }

        /// <summary>
        /// Gets or sets the "error_uri" parameter.
        /// </summary>
        public string ErrorUri
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.ErrorUri);
            set => SetParameter(OpenIddictConstants.Parameters.ErrorUri, value);
        }

        /// <summary>
        /// Gets or sets the "expires_in" parameter.
        /// </summary>
        public long? ExpiresIn
        {
            get => (long?) GetParameter(OpenIddictConstants.Parameters.ExpiresIn);
            set => SetParameter(OpenIddictConstants.Parameters.ExpiresIn, value);
        }

        /// <summary>
        /// Gets or sets the "id_token" parameter.
        /// </summary>
        public string IdToken
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.IdToken);
            set => SetParameter(OpenIddictConstants.Parameters.IdToken, value);
        }

        /// <summary>
        /// Gets or sets the "realm" parameter.
        /// </summary>
        public string Realm
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.Realm);
            set => SetParameter(OpenIddictConstants.Parameters.Realm, value);
        }

        /// <summary>
        /// Gets or sets the "refresh_token" parameter.
        /// </summary>
        public string RefreshToken
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.RefreshToken);
            set => SetParameter(OpenIddictConstants.Parameters.RefreshToken, value);
        }

        /// <summary>
        /// Gets or sets the "scope" parameter.
        /// </summary>
        public string Scope
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.Scope);
            set => SetParameter(OpenIddictConstants.Parameters.Scope, value);
        }

        /// <summary>
        /// Gets or sets the "state" parameter.
        /// </summary>
        public string State
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.State);
            set => SetParameter(OpenIddictConstants.Parameters.State, value);
        }

        /// <summary>
        /// Gets or sets the "token_type" parameter.
        /// </summary>
        public string TokenType
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.TokenType);
            set => SetParameter(OpenIddictConstants.Parameters.TokenType, value);
        }

        /// <summary>
        /// Gets or sets the "user_code" parameter.
        /// </summary>
        public string UserCode
        {
            get => (string) GetParameter(OpenIddictConstants.Parameters.UserCode);
            set => SetParameter(OpenIddictConstants.Parameters.UserCode, value);
        }
    }
}
