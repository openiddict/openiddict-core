using System;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace OpenIddict.Server
{
    /// <summary>
    /// Dispatches notifications by invoking the corresponding handlers.
    /// </summary>
    public class OpenIddictServerEventService : IOpenIddictServerEventService
    {
        private readonly IServiceProvider _provider;

        public OpenIddictServerEventService([NotNull] IServiceProvider provider)
        {
            _provider = provider;
        }

        /// <summary>
        /// Publishes a new event.
        /// </summary>
        /// <typeparam name="TEvent">The type of the event to publish.</typeparam>
        /// <param name="notification">The event to publish.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>A <see cref="Task"/> that can be used to monitor the asynchronous operation.</returns>
        public async Task PublishAsync<TEvent>([NotNull] TEvent notification, CancellationToken cancellationToken = default)
            where TEvent : class, IOpenIddictServerEvent
        {
            if (notification == null)
            {
                throw new ArgumentNullException(nameof(notification));
            }

            foreach (var handler in _provider.GetServices<IOpenIddictServerEventHandler<TEvent>>())
            {
                cancellationToken.ThrowIfCancellationRequested();

                await handler.HandleAsync(notification, cancellationToken);

                // Note: the following logic determines whether next handlers should be invoked
                // depending on whether the underlying event context was substantially updated.
                switch (notification)
                {
                    case MatchEndpoint value when value.Context.State != EventResultState.Continue: return;
                    case MatchEndpoint value when value.Context.IsAuthorizationEndpoint ||
                                                  value.Context.IsConfigurationEndpoint ||
                                                  value.Context.IsCryptographyEndpoint  ||
                                                  value.Context.IsIntrospectionEndpoint ||
                                                  value.Context.IsLogoutEndpoint        ||
                                                  value.Context.IsRevocationEndpoint    ||
                                                  value.Context.IsTokenEndpoint         ||
                                                  value.Context.IsUserinfoEndpoint: return;

                    case ExtractAuthorizationRequest value when value.Context.State != EventResultState.Continue: return;
                    case ExtractConfigurationRequest value when value.Context.State != EventResultState.Continue: return;
                    case ExtractCryptographyRequest  value when value.Context.State != EventResultState.Continue: return;
                    case ExtractIntrospectionRequest value when value.Context.State != EventResultState.Continue: return;
                    case ExtractLogoutRequest        value when value.Context.State != EventResultState.Continue: return;
                    case ExtractRevocationRequest    value when value.Context.State != EventResultState.Continue: return;
                    case ExtractTokenRequest         value when value.Context.State != EventResultState.Continue: return;
                    case ExtractUserinfoRequest      value when value.Context.State != EventResultState.Continue: return;

                    case ValidateAuthorizationRequest value when value.Context.State != EventResultState.Continue: return;
                    case ValidateConfigurationRequest value when value.Context.State != EventResultState.Continue: return;
                    case ValidateCryptographyRequest  value when value.Context.State != EventResultState.Continue: return;
                    case ValidateIntrospectionRequest value when value.Context.State != EventResultState.Continue: return;
                    case ValidateLogoutRequest        value when value.Context.State != EventResultState.Continue: return;
                    case ValidateRevocationRequest    value when value.Context.State != EventResultState.Continue: return;
                    case ValidateTokenRequest         value when value.Context.State != EventResultState.Continue: return;
                    case ValidateUserinfoRequest      value when value.Context.State != EventResultState.Continue: return;

                    case ValidateAuthorizationRequest value when value.Context.IsRejected: return;
                    case ValidateConfigurationRequest value when value.Context.IsRejected: return;
                    case ValidateCryptographyRequest  value when value.Context.IsRejected: return;
                    case ValidateIntrospectionRequest value when value.Context.IsRejected: return;
                    case ValidateLogoutRequest        value when value.Context.IsRejected: return;
                    case ValidateRevocationRequest    value when value.Context.IsRejected: return;
                    case ValidateTokenRequest         value when value.Context.IsRejected: return;
                    case ValidateUserinfoRequest      value when value.Context.IsRejected: return;

                    case ValidateIntrospectionRequest value when value.Context.IsSkipped: return;
                    case ValidateRevocationRequest    value when value.Context.IsSkipped: return;
                    case ValidateTokenRequest         value when value.Context.IsSkipped: return;

                    case HandleAuthorizationRequest value when value.Context.State != EventResultState.Continue: return;
                    case HandleConfigurationRequest value when value.Context.State != EventResultState.Continue: return;
                    case HandleCryptographyRequest  value when value.Context.State != EventResultState.Continue: return;
                    case HandleIntrospectionRequest value when value.Context.State != EventResultState.Continue: return;
                    case HandleLogoutRequest        value when value.Context.State != EventResultState.Continue: return;
                    case HandleRevocationRequest    value when value.Context.State != EventResultState.Continue: return;
                    case HandleTokenRequest         value when value.Context.State != EventResultState.Continue: return;
                    case HandleUserinfoRequest      value when value.Context.State != EventResultState.Continue: return;

                    case HandleAuthorizationRequest value when value.Context.Ticket != null: return;

                    case HandleTokenRequest value when value.Context.Ticket != null &&
                        !value.Context.Request.IsAuthorizationCodeGrantType() &&
                        !value.Context.Request.IsRefreshTokenGrantType(): return;

                    case HandleTokenRequest value when value.Context.Ticket == null &&
                        (value.Context.Request.IsAuthorizationCodeGrantType() ||
                         value.Context.Request.IsRefreshTokenGrantType()): return;

                    case HandleAuthorizationRequest value when value.Context.Ticket != null: return;

                    case ProcessChallengeResponse value when value.Context.State != EventResultState.Continue: return;
                    case ProcessSigninResponse    value when value.Context.State != EventResultState.Continue: return;
                    case ProcessSignoutResponse   value when value.Context.State != EventResultState.Continue: return;

                    case ProcessChallengeResponse value when value.Context.IsRejected: return;
                    case ProcessSigninResponse    value when value.Context.IsRejected: return;
                    case ProcessSignoutResponse   value when value.Context.IsRejected: return;

                    case ApplyAuthorizationResponse value when value.Context.State != EventResultState.Continue: return;
                    case ApplyConfigurationResponse value when value.Context.State != EventResultState.Continue: return;
                    case ApplyCryptographyResponse  value when value.Context.State != EventResultState.Continue: return;
                    case ApplyIntrospectionResponse value when value.Context.State != EventResultState.Continue: return;
                    case ApplyLogoutResponse        value when value.Context.State != EventResultState.Continue: return;
                    case ApplyRevocationResponse    value when value.Context.State != EventResultState.Continue: return;
                    case ApplyTokenResponse         value when value.Context.State != EventResultState.Continue: return;
                    case ApplyUserinfoResponse      value when value.Context.State != EventResultState.Continue: return;

                    case DeserializeAuthorizationCode value when value.Context.State != EventResultState.Continue: return;
                    case DeserializeAccessToken       value when value.Context.State != EventResultState.Continue: return;
                    case DeserializeIdentityToken     value when value.Context.State != EventResultState.Continue: return;
                    case DeserializeRefreshToken      value when value.Context.State != EventResultState.Continue: return;

                    case DeserializeAuthorizationCode value when value.Context.Ticket != null: return;
                    case DeserializeAccessToken       value when value.Context.Ticket != null: return;
                    case DeserializeIdentityToken     value when value.Context.Ticket != null: return;
                    case DeserializeRefreshToken      value when value.Context.Ticket != null: return;

                    case SerializeAuthorizationCode value when value.Context.State != EventResultState.Continue: return;
                    case SerializeAccessToken       value when value.Context.State != EventResultState.Continue: return;
                    case SerializeIdentityToken     value when value.Context.State != EventResultState.Continue: return;
                    case SerializeRefreshToken      value when value.Context.State != EventResultState.Continue: return;

                    case SerializeAuthorizationCode value when !string.IsNullOrEmpty(value.Context.AuthorizationCode): return;
                    case SerializeAccessToken       value when !string.IsNullOrEmpty(value.Context.AccessToken):       return;
                    case SerializeIdentityToken     value when !string.IsNullOrEmpty(value.Context.IdentityToken):     return;
                    case SerializeRefreshToken      value when !string.IsNullOrEmpty(value.Context.RefreshToken):      return;
                }
            }
        }
    }
}
