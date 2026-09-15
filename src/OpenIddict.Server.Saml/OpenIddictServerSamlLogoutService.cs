/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Xml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Extensions.OpenIddictSamlHelpers;
using static OpenIddict.Server.Saml.OpenIddictServerSamlConstants;
using static OpenIddict.Server.Saml.OpenIddictServerSamlHelpers;
using static OpenIddict.Server.Saml.OpenIddictServerSamlModels;
using Parameters = OpenIddict.Server.Saml.OpenIddictServerSamlConstants.Parameters;
using ProcessSessionTerminationContext = OpenIddict.Server.OpenIddictServerEvents.ProcessSessionTerminationContext;

namespace OpenIddict.Server.Saml;

/// <summary>
/// Provides the host-agnostic SAML 2.0 single logout operations (SAML profiles, 4.4): server-side session tracking,
/// logout request and response validation, session termination and logout propagation to the session participants.
/// </summary>
/// <remarks>
/// A server-side session entry (without application, sharing the login identifier of the user) is created for each service
/// provider an assertion is issued to: its identifier is used as the SessionIndex of the assertion. Terminating a session
/// (using the single logout endpoint, the OpenID Connect end session endpoint or <see cref="OpenIddictServerService"/>)
/// terminates all the sessions sharing its login identifier and notifies the SAML service providers (front-channel
/// HTTP-Redirect/HTTP-POST bindings or back-channel SOAP binding) and the OpenID Connect client applications.
/// </remarks>
public sealed class OpenIddictServerSamlLogoutService
{
    private const string StateHandlePrefix = "logout-state:";
    private const byte StateVersion = 1;

    /// <summary>
    /// Gets the name of the transaction property indicating that a session termination is processed by the SAML single
    /// logout service (in which case the front-channel participants are notified using a redirect chain).
    /// </summary>
    internal const string TerminationPropertyName = "OpenIddict.Server.Saml.LogoutTermination";

    private readonly IOpenIddictServerSamlSoapClient _client;
    private readonly ILogger<OpenIddictServerSamlLogoutService> _logger;
    private readonly IOptionsMonitor<OpenIddictServerSamlOptions> _options;
    private readonly IServiceProvider _provider;
    private readonly IOpenIddictServerSamlReplayCache _replayCache;
    private readonly OpenIddictServerSamlService _service;
    private readonly IOpenIddictServerSamlArtifactStore _store;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerSamlLogoutService"/> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="options">The SAML options.</param>
    /// <param name="provider">The service provider.</param>
    /// <param name="service">The SAML service.</param>
    /// <param name="replayCache">The replay cache.</param>
    /// <param name="store">The store used to persist the logout states (the artifact store).</param>
    /// <param name="client">The SOAP client.</param>
    public OpenIddictServerSamlLogoutService(
        ILogger<OpenIddictServerSamlLogoutService> logger,
        IOptionsMonitor<OpenIddictServerSamlOptions> options,
        IServiceProvider provider,
        OpenIddictServerSamlService service,
        IOpenIddictServerSamlReplayCache replayCache,
        IOpenIddictServerSamlArtifactStore store,
        IOpenIddictServerSamlSoapClient client)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _service = service ?? throw new ArgumentNullException(nameof(service));
        _replayCache = replayCache ?? throw new ArgumentNullException(nameof(replayCache));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    /// <summary>
    /// Creates (or reuses) the server-side session entry representing the session of the user at the service provider
    /// and returns the assertion descriptor whose SessionIndex is the identifier of the session entry. When single logout
    /// is not enabled, the assertion descriptor is returned unchanged.
    /// </summary>
    /// <param name="context">The assertion context.</param>
    /// <param name="assertion">The assertion descriptor returned by the assertion provider.</param>
    /// <returns>The assertion descriptor.</returns>
    public ValueTask<AssertionDescriptor> AttachSessionAsync(AssertionContext context, AssertionDescriptor assertion)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(assertion);

        if (!_options.CurrentValue.EnableSingleLogout)
        {
            return new(assertion);
        }

        return ExecuteAsync(context, assertion);

        async ValueTask<AssertionDescriptor> ExecuteAsync(AssertionContext context, AssertionDescriptor assertion)
        {
            var options = _options.CurrentValue;
            var server = GetServerOptions();
            var manager = GetSessionManager();
            var cancellationToken = context.CancellationToken;

            var provider = context.ServiceProvider.EntityId!;
            var subject = GetSubject(context.Principal) ?? assertion.NameId;
            var login = GetLoginId(context.Principal);

            string? identifier = null;

            // When the same user logs in again to the same service provider, reuse the session created for the same login.
            if (!string.IsNullOrEmpty(login))
            {
                await foreach (var session in manager.FindAsync((subject, login, null, null, Statuses.Valid), cancellationToken))
                {
                    if (!string.IsNullOrEmpty(await manager.GetApplicationIdAsync(session, cancellationToken)) ||
                        await manager.HasExpiredAsync(session, cancellationToken))
                    {
                        continue;
                    }

                    var properties = await manager.GetPropertiesAsync(session, cancellationToken);
                    if (!string.Equals(GetProperty(properties, SessionProperties.ServiceProvider), provider, StringComparison.Ordinal) ||
                        !string.Equals(GetProperty(properties, SessionProperties.NameId), assertion.NameId, StringComparison.Ordinal) ||
                        !string.Equals(GetProperty(properties, SessionProperties.NameIdFormat), assertion.NameIdFormat, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    identifier = await manager.GetIdAsync(session, cancellationToken);
                    break;
                }
            }

            if (string.IsNullOrEmpty(identifier))
            {
                var date = options.TimeProvider.GetUtcNow();

                var descriptor = new OpenIddictSessionDescriptor
                {
                    CreationDate = date,
                    ExpirationDate = OpenIddictServerHelpers.ComputeSessionExpirationDate(server, date, date),
                    LastActivityDate = date,
                    LoginId = string.IsNullOrEmpty(login) ? null : login,
                    Status = Statuses.Valid,
                    Subject = subject
                };

                descriptor.Properties[SessionProperties.ServiceProvider] = CreateJsonString(provider);
                descriptor.Properties[SessionProperties.NameId] = CreateJsonString(assertion.NameId);
                descriptor.Properties[SessionProperties.NameIdFormat] = CreateJsonString(assertion.NameIdFormat);

                identifier = await manager.GetIdAsync(await manager.CreateAsync(descriptor, cancellationToken), cancellationToken);
            }

            _logger.LogInformation(6800, SR.GetResourceString(SR.ID6800), identifier, provider);

            return assertion with { SessionIndex = identifier };
        }
    }

    /// <summary>
    /// Validates a logout request sent using the HTTP-Redirect binding.
    /// </summary>
    /// <param name="query">The raw (URL-encoded) query string of the request.</param>
    /// <param name="endpoint">The absolute URL of the single logout endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<LogoutRequestResult> ValidateRedirectLogoutRequestAsync(
        string? query, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ValidateRequestAsync(DecodeRedirectMessage(query, Parameters.SamlRequest), endpoint, cancellationToken);
    }

    /// <summary>
    /// Validates a logout request sent using the HTTP-POST binding.
    /// </summary>
    /// <param name="request">The SAMLRequest form parameter.</param>
    /// <param name="relayState">The RelayState form parameter, if any.</param>
    /// <param name="endpoint">The absolute URL of the single logout endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<LogoutRequestResult> ValidatePostLogoutRequestAsync(
        string? request, string? relayState, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ValidateRequestAsync(DecodePostMessage(request, relayState), endpoint, cancellationToken);
    }

    /// <summary>
    /// Validates a logout response sent using the HTTP-Redirect binding.
    /// </summary>
    /// <param name="query">The raw (URL-encoded) query string of the request.</param>
    /// <param name="endpoint">The absolute URL of the single logout endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<LogoutResponseResult> ValidateRedirectLogoutResponseAsync(
        string? query, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ValidateResponseAsync(DecodeRedirectMessage(query, Parameters.SamlResponse), endpoint, cancellationToken);
    }

    /// <summary>
    /// Validates a logout response sent using the HTTP-POST binding.
    /// </summary>
    /// <param name="response">The SAMLResponse form parameter.</param>
    /// <param name="relayState">The RelayState form parameter, if any.</param>
    /// <param name="endpoint">The absolute URL of the single logout endpoint.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The validation result.</returns>
    public ValueTask<LogoutResponseResult> ValidatePostLogoutResponseAsync(
        string? response, string? relayState, Uri endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        return ValidateResponseAsync(DecodePostMessage(response, relayState), endpoint, cancellationToken);
    }

    /// <summary>
    /// Processes a validated logout request: the sessions identified by the request (SessionIndex or, when no session index
    /// is specified, the sessions of the NameID at the service provider for the login of the authenticated user) are terminated,
    /// the logout is propagated to the other session participants and the logout response is returned to the service provider
    /// once all the front-channel participants were notified (SAML profiles, 4.4.3).
    /// </summary>
    /// <remarks>
    /// Requests that don't match any valid session are acknowledged with a Success status, as the principal no longer has a
    /// session at the identity provider. The user is only signed out locally (see <see cref="LogoutAction.SignOut"/>) when
    /// a terminated session belongs to the login of the authenticated user.
    /// </remarks>
    /// <param name="result">The successful validation result.</param>
    /// <param name="principal">The principal currently authenticated by the host, if any.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The action the host must apply.</returns>
    public ValueTask<LogoutAction> ProcessLogoutRequestAsync(LogoutRequestResult result,
        ClaimsPrincipal? principal, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (!result.Succeeded || result.Request is null || result.ServiceProvider?.EntityId is not { Length: > 0 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID01006), nameof(result));
        }

        EnsureEnabled();

        return ExecuteAsync(result, principal, cancellationToken);

        async ValueTask<LogoutAction> ExecuteAsync(LogoutRequestResult result, ClaimsPrincipal? principal, CancellationToken cancellationToken)
        {
            var manager = GetSessionManager();
            var request = result.Request!;

            var login = principal?.Identity?.IsAuthenticated is true ? GetLoginId(principal) : null;
            var subject = principal?.Identity?.IsAuthenticated is true ? GetSubject(principal) : null;

            List<object> sessions = [];
            HashSet<string> identifiers = new(StringComparer.Ordinal);

            if (request.SessionIndexes.Count is not 0)
            {
                foreach (var index in request.SessionIndexes)
                {
                    if (await manager.FindByIdAsync(index, cancellationToken) is object session &&
                        await IsMatchingSessionAsync(session) && identifiers.Add(index))
                    {
                        sessions.Add(session);
                    }
                }
            }

            // Note: when no SessionIndex is specified, all the sessions of the principal at the service provider must be
            // terminated (SAML core, 3.7.3.2). Since NameIDs can't be mapped to users, only the sessions belonging to the
            // login of the authenticated user are considered (the other sessions expire or are terminated separately).
            else if (!string.IsNullOrEmpty(login))
            {
                await foreach (var session in manager.FindByLoginIdAsync(login, cancellationToken))
                {
                    if (await IsMatchingSessionAsync(session) &&
                        identifiers.Add((await manager.GetIdAsync(session, cancellationToken))!))
                    {
                        sessions.Add(session);
                    }
                }
            }

            _logger.LogInformation(6802, SR.GetResourceString(SR.ID6802), request.Issuer, sessions.Count);

            var signOut = false;

            foreach (var session in sessions)
            {
                var candidate = await manager.GetLoginIdAsync(session, cancellationToken);
                if ((!string.IsNullOrEmpty(login) && string.Equals(candidate, login, StringComparison.Ordinal)) ||
                    (string.IsNullOrEmpty(candidate) && !string.IsNullOrEmpty(subject) &&
                     string.Equals(await manager.GetSubjectAsync(session, cancellationToken), subject, StringComparison.Ordinal)))
                {
                    signOut = true;
                    break;
                }
            }

            var state = new LogoutState
            {
                InitiatorBinding = request.Binding,
                InitiatorRequestId = request.Id,
                InitiatorServiceProvider = request.Issuer,
                RelayState = result.RelayState
            };

            var terminated = await TerminateAsync(sessions, state, cancellationToken);

            return await ContinueAsync(state, signOut, terminated, cancellationToken);

            async ValueTask<bool> IsMatchingSessionAsync(object session)
            {
                if (!await manager.HasStatusAsync(session, Statuses.Valid, cancellationToken) ||
                    !string.IsNullOrEmpty(await manager.GetApplicationIdAsync(session, cancellationToken)))
                {
                    return false;
                }

                var properties = await manager.GetPropertiesAsync(session, cancellationToken);
                if (!string.Equals(GetProperty(properties, SessionProperties.ServiceProvider), request.Issuer, StringComparison.Ordinal) ||
                    !string.Equals(GetProperty(properties, SessionProperties.NameId), request.NameId, StringComparison.Ordinal))
                {
                    return false;
                }

                // Note: the formats are only compared when they are both explicitly specified.
                var format = GetProperty(properties, SessionProperties.NameIdFormat);
                return request.NameIdFormat is null or NameIdFormats.Unspecified || format is null or NameIdFormats.Unspecified ||
                       string.Equals(format, request.NameIdFormat, StringComparison.Ordinal);
            }
        }
    }

    /// <summary>
    /// Processes a validated logout response returned by a service provider the logout was propagated to and returns
    /// the next action (logout request sent to the next participant or logout response returned to the initiator).
    /// Responses that don't correspond to a pending logout request (e.g responses to logout requests rendered in
    /// front-channel iframes) complete the operation without any navigation.
    /// </summary>
    /// <param name="result">The successful validation result.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The action the host must apply.</returns>
    public ValueTask<LogoutAction> ProcessLogoutResponseAsync(LogoutResponseResult result, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (!result.Succeeded || string.IsNullOrEmpty(result.InResponseTo) || result.ServiceProvider?.EntityId is not { Length: > 0 })
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID01006), nameof(result));
        }

        EnsureEnabled();

        return ExecuteAsync(result, cancellationToken);

        async ValueTask<LogoutAction> ExecuteAsync(LogoutResponseResult result, CancellationToken cancellationToken)
        {
            var message = await _store.RemoveAsync(StateHandlePrefix + result.InResponseTo, cancellationToken);
            if (message is null || message.ExpirationDate < _options.CurrentValue.TimeProvider.GetUtcNow() ||
                DeserializeState(message.Message) is not LogoutState state)
            {
                _logger.LogInformation(6806, SR.GetResourceString(SR.ID6806), result.InResponseTo);

                return new LogoutAction();
            }

            // Note: the state is removed even if the response was not returned by the expected service provider.
            if (!string.Equals(message.ServiceProvider, result.ServiceProvider!.EntityId, StringComparison.Ordinal) ||
                !string.Equals(result.Status, StatusCodes.Success, StringComparison.Ordinal))
            {
                _logger.LogWarning(6805, SR.GetResourceString(SR.ID6805), result.ServiceProvider.EntityId, result.Status);

                state.PartialLogout = true;
            }

            return await ContinueAsync(state, signOut: false, terminated: [], cancellationToken);
        }
    }

    /// <summary>
    /// Starts an identity provider-initiated single logout: all the valid sessions sharing the login identifier of the
    /// specified principal are terminated, the logout is propagated to their participants and the user agent is finally
    /// redirected to the return URL, if specified.
    /// </summary>
    /// <param name="principal">The authenticated principal.</param>
    /// <param name="returnUrl">The local URL the user agent is redirected to once the logout is completed, if any.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
    /// <returns>The action the host must apply.</returns>
    public ValueTask<LogoutAction> StartLogoutAsync(ClaimsPrincipal principal, Uri? returnUrl, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        EnsureEnabled();

        return ExecuteAsync(principal, returnUrl, cancellationToken);

        async ValueTask<LogoutAction> ExecuteAsync(ClaimsPrincipal principal, Uri? returnUrl, CancellationToken cancellationToken)
        {
            var manager = GetSessionManager();

            List<object> sessions = [];

            if (principal.Identity?.IsAuthenticated is true && GetLoginId(principal) is { Length: > 0 } login)
            {
                var subject = GetSubject(principal);

                await foreach (var session in manager.FindByLoginIdAsync(login, cancellationToken))
                {
                    if (await manager.HasStatusAsync(session, Statuses.Valid, cancellationToken) && (string.IsNullOrEmpty(subject) ||
                        string.Equals(await manager.GetSubjectAsync(session, cancellationToken), subject, StringComparison.Ordinal)))
                    {
                        sessions.Add(session);
                    }
                }
            }

            var state = new LogoutState { ReturnUrl = returnUrl?.OriginalString };

            var terminated = await TerminateAsync(sessions, state, cancellationToken);

            return await ContinueAsync(state, signOut: true, terminated, cancellationToken);
        }
    }

    /// <summary>
    /// Creates the action returning an error logout response to the service provider that sent an invalid logout request.
    /// </summary>
    /// <param name="result">The failed validation result, that must allow returning an error to the service provider.</param>
    /// <returns>The action the host must apply.</returns>
    public LogoutAction CreateErrorResponseAction(LogoutRequestResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (result.Succeeded || !result.CanReturnErrorToServiceProvider ||
            result.ServiceProvider?.SingleLogoutServiceUrl is not Uri url)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID01006), nameof(result));
        }

        var provider = result.ServiceProvider;
        var destination = provider.SingleLogoutServiceResponseUrl ?? url;
        var binding = GetFrontchannelBinding(provider, result.Binding);

        var response = CreateLogoutResponse(destination, result.RequestId, result.Status!,
            result.SecondLevelStatus, result.ErrorDescription, signed: binding is Bindings.HttpPost);

        _logger.LogInformation(6809, SR.GetResourceString(SR.ID6809), result.Status, provider.EntityId);

        return CreateMessageAction(destination, binding, Parameters.SamlResponse, response,
            result.RelayState, frames: [], signOut: false, partial: false, terminated: []);
    }

    /// <summary>
    /// Creates the HTML page rendering the front-channel logout URIs of a logout action (in hidden iframes) and, once
    /// they are loaded (or after 3 seconds), redirecting the user agent or automatically posting the SAML message.
    /// </summary>
    /// <param name="action">The logout action.</param>
    /// <param name="nonce">The nonce attached to the inline script (that must be allowed by the content security policy).</param>
    /// <returns>The HTML page.</returns>
    public static string CreateLogoutPage(LogoutAction action, string nonce)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        var builder = new StringBuilder()
            .Append("<!doctype html><html><head><meta charset=\"utf-8\" /><title>Signing out...</title></head><body>");

        foreach (var uri in action.FrontchannelLogoutUris)
        {
            builder.Append("<iframe hidden width=\"0\" height=\"0\" src=\"").Append(WebUtility.HtmlEncode(uri.AbsoluteUri)).Append("\"></iframe>");
        }

        if (action.FormPostUrl is not null)
        {
            builder.Append("<form id=\"saml\" method=\"post\" action=\"").Append(WebUtility.HtmlEncode(action.FormPostUrl.AbsoluteUri)).Append("\">");

            foreach (var field in action.FormFields)
            {
                builder.Append("<input type=\"hidden\" name=\"").Append(WebUtility.HtmlEncode(field.Key)).Append("\" value=\"")
                       .Append(WebUtility.HtmlEncode(field.Value)).Append("\" />");
            }

            builder.Append("<noscript><button type=\"submit\">Continue</button></noscript></form>");
        }

        else if (action.RedirectUrl is not null)
        {
            builder.Append("<noscript><a href=\"").Append(WebUtility.HtmlEncode(action.RedirectUrl.OriginalString)).Append("\">Continue</a></noscript>");
        }

        else
        {
            builder.Append("<p>").Append(WebUtility.HtmlEncode(SR.GetResourceString(SR.ID8200))).Append("</p>");
        }

        if (action.FormPostUrl is not null || action.RedirectUrl is not null)
        {
            builder.Append("<script nonce=\"").Append(WebUtility.HtmlEncode(nonce)).Append("\">(function () {")
                   .Append("var frames = document.getElementsByTagName('iframe'), pending = frames.length, done = false;")
                   .Append("function next() { if (done) { return; } done = true; ");

            builder.Append(action.FormPostUrl is not null
                ? "document.getElementById('saml').submit();"
                : "window.location.replace(\"" + JavaScriptEncoder.Default.Encode(action.RedirectUrl!.OriginalString) + "\");");

            builder.Append("}")
                   .Append("for (var i = 0; i < frames.length; i++) { frames[i].addEventListener('load', function () { if (--pending <= 0) { next(); } }); }")
                   .Append("if (pending === 0) { next(); } window.setTimeout(next, 3000); })();</script>");
        }

        return builder.Append("</body></html>").ToString();
    }

    /// <summary>
    /// Creates the content security policy attached to the page returned by <see cref="CreateLogoutPage(LogoutAction, string)"/>.
    /// </summary>
    /// <param name="action">The logout action.</param>
    /// <param name="nonce">The nonce attached to the inline script.</param>
    /// <returns>The content security policy.</returns>
    public static string CreateLogoutContentSecurityPolicy(LogoutAction action, string nonce)
    {
        ArgumentNullException.ThrowIfNull(action);
        ArgumentException.ThrowIfNullOrEmpty(nonce);

        var builder = new StringBuilder("default-src 'none'; script-src 'nonce-").Append(nonce).Append("'; ");

        if (action.FrontchannelLogoutUris.Count is not 0)
        {
            builder.Append("frame-src ").Append(string.Join(' ', action.FrontchannelLogoutUris
                .Select(static uri => uri.GetLeftPart(UriPartial.Authority))
                .Distinct(StringComparer.OrdinalIgnoreCase))).Append("; ");
        }

        if (action.FormPostUrl is not null)
        {
            builder.Append("form-action ").Append(action.FormPostUrl.GetLeftPart(UriPartial.Authority)).Append("; ");
        }

        return builder.Append("frame-ancestors 'none'; base-uri 'none'").ToString();
    }

    /// <summary>
    /// Resolves the SAML service provider sessions attached to a session termination and notifies them: service providers
    /// using the SOAP binding are notified directly, front-channel service providers are either added to the redirect chain
    /// (when the termination is processed by this service) or exposed as front-channel logout URIs (HTTP-Redirect binding).
    /// </summary>
    internal async ValueTask ProcessSessionTerminationAsync(ProcessSessionTerminationContext context)
    {
        var options = _options.CurrentValue;
        if (!options.EnableSingleLogout || context.Sessions.Count is 0 ||
            context.ServiceProvider.GetService<IOpenIddictSessionManager>() is not IOpenIddictSessionManager manager)
        {
            return;
        }

        var termination = context.Transaction.Properties.TryGetValue(TerminationPropertyName, out var value) ? value as TerminationState : null;

        List<(LogoutParticipant Participant, OpenIddictServerSamlServiceProvider Provider)> soap = [];

        foreach (var session in context.Sessions)
        {
            var properties = await manager.GetPropertiesAsync(session, context.CancellationToken);
            if (GetProperty(properties, SessionProperties.ServiceProvider) is not { Length: > 0 } entityId ||
                GetProperty(properties, SessionProperties.NameId) is not { Length: > 0 } nameId ||
                await _service.FindServiceProviderAsync(entityId, context.CancellationToken) is not { SingleLogoutServiceUrl: Uri url } provider)
            {
                continue;
            }

            var participant = new LogoutParticipant
            {
                Binding = provider.SingleLogoutServiceBinding ?? Bindings.HttpRedirect,
                NameId = nameId,
                NameIdFormat = GetProperty(properties, SessionProperties.NameIdFormat),
                ServiceProvider = entityId,
                SessionId = (await manager.GetIdAsync(session, context.CancellationToken))!,
                Url = url
            };

            if (participant.Binding is Bindings.Soap)
            {
                soap.Add((participant, provider));
            }

            else if (termination is not null)
            {
                termination.FrontchannelParticipants.Add(participant);
            }

            // When the termination is not processed by this service (e.g OpenID Connect end session endpoint), the service
            // providers using the HTTP-Redirect binding are notified using front-channel logout URIs (rendered in iframes).
            else if (context.ResolveFrontchannelLogoutUris)
            {
                if (participant.Binding is not Bindings.HttpRedirect)
                {
                    _logger.LogInformation(6808, SR.GetResourceString(SR.ID6808), entityId);
                    continue;
                }

                var request = CreateLogoutRequest(CreateIdentifier(), url, participant, signed: false);
                var uri = CreateRedirectUrl(url, Parameters.SamlRequest, request, relayState: null);

                if (!context.FrontchannelLogoutUris.Contains(uri))
                {
                    context.FrontchannelLogoutUris.Add(uri);
                }

                _logger.LogInformation(6803, SR.GetResourceString(SR.ID6803), entityId, participant.Binding);
            }
        }

        // Note: SOAP logout requests are only sent when the sessions are actually terminated.
        if (soap.Count is 0 || (!context.RevokeSessions && !context.SendBackchannelLogoutRequests))
        {
            return;
        }

        var results = await Task.WhenAll(soap.Select(entry => SendSoapLogoutRequestAsync(
            entry.Participant, entry.Provider, context.CancellationToken)));

        if (termination is not null && Array.Exists(results, static result => !result))
        {
            termination.PartialLogout = true;
        }
    }

    private async Task<bool> SendSoapLogoutRequestAsync(LogoutParticipant participant,
        OpenIddictServerSamlServiceProvider provider, CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;
        var identifier = CreateIdentifier();

        // Note: messages sent using the SOAP binding are signed using an enveloped signature (SAML profiles, 4.4.4.1).
        var envelope = new StringBuilder()
            .Append("<soap:Envelope xmlns:soap=\"").Append(Namespaces.Soap11).Append("\"><soap:Body>")
            .Append(CreateLogoutRequest(identifier, participant.Url, participant, signed: true))
            .Append("</soap:Body></soap:Envelope>")
            .ToString();

        string? content;

        using (var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            source.CancelAfter(options.SingleLogoutTimeout);

            try
            {
                _logger.LogInformation(6803, SR.GetResourceString(SR.ID6803), participant.ServiceProvider, Bindings.Soap);

                content = await _client.SendAsync(participant.Url, envelope, source.Token);
            }

            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                content = null;
            }
        }

        if (string.IsNullOrEmpty(content))
        {
            _logger.LogWarning(6804, SR.GetResourceString(SR.ID6804), participant.ServiceProvider, SR.GetResourceString(SR.ID2246));
            return false;
        }

        var data = Encoding.UTF8.GetBytes(content);
        if (LoadDocument(data, options.MaximumMessageSize, out _) is not XmlDocument document ||
            document.DocumentElement is not XmlElement root ||
            !IsElement(root, Elements.Envelope, Namespaces.Soap11) ||
            GetChildElements(root, Elements.Body, Namespaces.Soap11) is not [XmlElement body] ||
            GetChildElements(body, Elements.LogoutResponse, Namespaces.Protocol) is not [XmlElement response] ||
            !string.Equals(response.GetAttribute("InResponseTo"), identifier, StringComparison.Ordinal) ||
            GetChildElements(response, Elements.Issuer, Namespaces.Assertion) is not [XmlElement issuer] ||
            !string.Equals(GetTextContent(issuer), provider.EntityId, StringComparison.Ordinal))
        {
            _logger.LogWarning(6804, SR.GetResourceString(SR.ID6804), participant.ServiceProvider, SR.GetResourceString(SR.ID2501));
            return false;
        }

        // Note: SOAP responses are authenticated using the XML signature when signing certificates are registered.
        // Otherwise, the response is only authenticated by the TLS server authentication (SAML bindings, 3.2.4).
        if (provider.SigningCertificates.Count is not 0 &&
            ValidateMessageSignature(response, provider.SigningCertificates) is not SignatureValidationResult.Valid)
        {
            _logger.LogWarning(6804, SR.GetResourceString(SR.ID6804), participant.ServiceProvider, SR.GetResourceString(SR.ID2504));
            return false;
        }

        var status = GetStatus(response).Status;
        if (!string.Equals(status, StatusCodes.Success, StringComparison.Ordinal))
        {
            _logger.LogWarning(6805, SR.GetResourceString(SR.ID6805), participant.ServiceProvider, status);
            return false;
        }

        return true;
    }

    private async ValueTask<List<string>> TerminateAsync(List<object> sessions, LogoutState state, CancellationToken cancellationToken)
    {
        List<string> identifiers = [];

        if (sessions.Count is 0)
        {
            return identifiers;
        }

        var server = GetServerOptions();
        var manager = GetSessionManager();
        var dispatcher = _provider.GetRequiredService<IOpenIddictServerDispatcher>();

        var termination = new TerminationState();

        foreach (var session in sessions)
        {
            var identifier = (await manager.GetIdAsync(session, cancellationToken))!;

            var transaction = new OpenIddictServerTransaction
            {
                CancellationToken = cancellationToken,
                Options = server,
                ServiceProvider = _provider
            };

            transaction.Properties[TerminationPropertyName] = termination;

            // Note: the sessions sharing the login identifier of the terminated session are also terminated (and their
            // participants notified), which ensures a logout initiated using SAML also terminates the OpenID Connect sessions.
            var context = new ProcessSessionTerminationContext(transaction)
            {
                SessionId = identifier,
                RevokeSessions = true,
                RevokeAuthorizations = server.RevokeAuthorizationsOnSessionTermination,
                SendBackchannelLogoutRequests = server.EnableBackchannelLogout,
                ResolveFrontchannelLogoutUris = server.EnableFrontchannelLogout
            };

            await dispatcher.DispatchAsync(context);

            if (context.IsRejected)
            {
                _logger.LogWarning(6807, SR.GetResourceString(SR.ID6807), identifier, context.Error, context.ErrorDescription);

                state.PartialLogout = true;
                continue;
            }

            foreach (var entry in context.Sessions)
            {
                identifiers.Add((await manager.GetIdAsync(entry, cancellationToken))!);
            }

            foreach (var uri in context.FrontchannelLogoutUris)
            {
                if (!state.FrontchannelLogoutUris.Contains(uri))
                {
                    state.FrontchannelLogoutUris.Add(uri);
                }
            }

            if (context.FailedParticipants.Count is not 0)
            {
                state.PartialLogout = true;
            }
        }

        if (termination.PartialLogout)
        {
            state.PartialLogout = true;
        }

        // Note: the service provider that initiated the logout is not sent a logout request (SAML profiles, 4.4.3.3).
        foreach (var participant in termination.FrontchannelParticipants)
        {
            if (!string.Equals(participant.ServiceProvider, state.InitiatorServiceProvider, StringComparison.Ordinal) &&
                !state.Pending.Exists(candidate => string.Equals(candidate.SessionId, participant.SessionId, StringComparison.Ordinal)))
            {
                state.Pending.Add(participant);
            }
        }

        return identifiers;
    }

    private async ValueTask<LogoutAction> ContinueAsync(LogoutState state, bool signOut,
        IReadOnlyList<string> terminated, CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;

        // Note: the front-channel logout URIs are rendered with the first action returned to the user agent.
        List<Uri> frames = [.. state.FrontchannelLogoutUris];
        state.FrontchannelLogoutUris.Clear();

        // Propagate the logout to the front-channel participants one at a time (SAML profiles, 4.4.3.4).
        while (state.Pending.Count is not 0)
        {
            var participant = state.Pending[0];
            state.Pending.RemoveAt(0);

            if (await _service.FindServiceProviderAsync(participant.ServiceProvider, cancellationToken) is not
                { SingleLogoutServiceUrl: Uri url, EntityId: string entityId } provider ||
                (provider.SingleLogoutServiceBinding ?? Bindings.HttpRedirect) is not (Bindings.HttpRedirect or Bindings.HttpPost))
            {
                state.PartialLogout = true;
                continue;
            }

            var binding = provider.SingleLogoutServiceBinding ?? Bindings.HttpRedirect;
            var identifier = CreateIdentifier();
            var request = CreateLogoutRequest(identifier, url, participant with { Url = url }, signed: binding is Bindings.HttpPost);

            await _store.AddAsync(StateHandlePrefix + identifier, new ArtifactMessage
            {
                ExpirationDate = options.TimeProvider.GetUtcNow() + options.LogoutStateLifetime,
                Message = SerializeState(state),
                ServiceProvider = entityId
            }, cancellationToken);

            _logger.LogInformation(6803, SR.GetResourceString(SR.ID6803), entityId, binding);

            return CreateMessageAction(url, binding, Parameters.SamlRequest, request,
                relayState: null, frames, signOut, state.PartialLogout, terminated);
        }

        if (!string.IsNullOrEmpty(state.InitiatorServiceProvider) &&
            await _service.FindServiceProviderAsync(state.InitiatorServiceProvider!, cancellationToken) is
                { SingleLogoutServiceUrl: Uri location } initiator)
        {
            var destination = initiator.SingleLogoutServiceResponseUrl ?? location;
            var binding = GetFrontchannelBinding(initiator, state.InitiatorBinding);

            // Note: PartialLogout is returned as a second-level status code when the logout
            // couldn't be propagated to all the session participants (SAML core, 3.2.2.2).
            var response = CreateLogoutResponse(destination, state.InitiatorRequestId, StatusCodes.Success,
                state.PartialLogout ? StatusCodes.PartialLogout : null, message: null, signed: binding is Bindings.HttpPost);

            _logger.LogInformation(6809, SR.GetResourceString(SR.ID6809), StatusCodes.Success, initiator.EntityId);

            return CreateMessageAction(destination, binding, Parameters.SamlResponse, response,
                state.RelayState, frames, signOut, state.PartialLogout, terminated);
        }

        return new LogoutAction
        {
            FrontchannelLogoutUris = frames,
            PartialLogout = state.PartialLogout,
            RedirectUrl = string.IsNullOrEmpty(state.ReturnUrl) ? null : new Uri(state.ReturnUrl, UriKind.RelativeOrAbsolute),
            SignOut = signOut,
            TerminatedSessionIds = terminated
        };
    }

    private LogoutAction CreateMessageAction(Uri url, string binding, string parameter, string message, string? relayState,
        IReadOnlyList<Uri> frames, bool signOut, bool partial, IReadOnlyList<string> terminated)
    {
        if (binding is Bindings.HttpPost)
        {
            List<KeyValuePair<string, string>> fields = [new(parameter, Convert.ToBase64String(Encoding.UTF8.GetBytes(message)))];

            if (relayState is not null)
            {
                fields.Add(new(Parameters.RelayState, relayState));
            }

            return new LogoutAction
            {
                FormFields = fields,
                FormPostUrl = url,
                FrontchannelLogoutUris = frames,
                PartialLogout = partial,
                SignOut = signOut,
                TerminatedSessionIds = terminated
            };
        }

        return new LogoutAction
        {
            FrontchannelLogoutUris = frames,
            PartialLogout = partial,
            RedirectUrl = CreateRedirectUrl(url, parameter, message, relayState),
            SignOut = signOut,
            TerminatedSessionIds = terminated
        };
    }

    // Note: the HTTP-Redirect binding uses a detached signature computed over the URL-encoded parameters (SAML bindings, 3.4.4.1).
    private Uri CreateRedirectUrl(Uri url, string parameter, string message, string? relayState)
    {
        var options = _options.CurrentValue;

        var query = new StringBuilder()
            .Append(parameter).Append('=').Append(Uri.EscapeDataString(Convert.ToBase64String(Deflate(Encoding.UTF8.GetBytes(message)))));

        if (relayState is not null)
        {
            query.Append('&').Append(Parameters.RelayState).Append('=').Append(Uri.EscapeDataString(relayState));
        }

        query.Append('&').Append(Parameters.SignatureAlgorithm).Append('=').Append(Uri.EscapeDataString(options.SignatureAlgorithm));

        using (var key = OpenIddictServerSamlService.GetSigningCertificate(options).GetRSAPrivateKey() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0566)))
        {
            var signature = CreateRedirectSignature(query.ToString(), key, options.SignatureAlgorithm);

            query.Append('&').Append(Parameters.Signature).Append('=').Append(Uri.EscapeDataString(signature));
        }

        var builder = new StringBuilder(url.AbsoluteUri);
        builder.Append(url.Query switch
        {
            { Length: > 1 } => "&",
            "?" => string.Empty,
            _ => "?"
        });

        return new Uri(builder.Append(query).ToString(), UriKind.Absolute);
    }

    private string CreateLogoutRequest(string identifier, Uri destination, LogoutParticipant participant, bool signed)
    {
        var options = _options.CurrentValue;
        var now = options.TimeProvider.GetUtcNow();

        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };

        var request = document.CreateElement("samlp", Elements.LogoutRequest, Namespaces.Protocol);
        request.SetAttribute("xmlns:samlp", Namespaces.Protocol);
        request.SetAttribute("xmlns:saml", Namespaces.Assertion);
        request.SetAttribute("ID", identifier);
        request.SetAttribute("Version", "2.0");
        request.SetAttribute("IssueInstant", FormatInstant(now));
        request.SetAttribute("Destination", destination.AbsoluteUri);
        request.SetAttribute("NotOnOrAfter", FormatInstant(now + options.LogoutStateLifetime));
        request.SetAttribute("Reason", LogoutReasons.User);
        document.AppendChild(request);

        var issuer = AppendElement(request, "saml", Elements.Issuer, Namespaces.Assertion, options.EntityId);

        var name = AppendElement(request, "saml", Elements.NameId, Namespaces.Assertion, participant.NameId);
        if (!string.IsNullOrEmpty(participant.NameIdFormat))
        {
            name.SetAttribute("Format", participant.NameIdFormat);
        }

        AppendElement(request, "samlp", Elements.SessionIndex, Namespaces.Protocol, participant.SessionId);

        if (signed)
        {
            SignElement(request, issuer, OpenIddictServerSamlService.GetSigningCertificate(options),
                options.SignatureAlgorithm, options.DigestAlgorithm);
        }

        return document.OuterXml;
    }

    private string CreateLogoutResponse(Uri destination, string? inResponseTo, string status,
        string? secondLevelStatus, string? message, bool signed)
    {
        var options = _options.CurrentValue;

        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };

        var response = document.CreateElement("samlp", Elements.LogoutResponse, Namespaces.Protocol);
        response.SetAttribute("xmlns:samlp", Namespaces.Protocol);
        response.SetAttribute("xmlns:saml", Namespaces.Assertion);
        response.SetAttribute("ID", CreateIdentifier());
        response.SetAttribute("Version", "2.0");
        response.SetAttribute("IssueInstant", FormatInstant(options.TimeProvider.GetUtcNow()));
        response.SetAttribute("Destination", destination.AbsoluteUri);

        if (!string.IsNullOrEmpty(inResponseTo))
        {
            response.SetAttribute("InResponseTo", inResponseTo);
        }

        document.AppendChild(response);

        var issuer = AppendElement(response, "saml", Elements.Issuer, Namespaces.Assertion, options.EntityId);

        var element = AppendElement(response, "samlp", Elements.Status, Namespaces.Protocol);
        var code = AppendElement(element, "samlp", Elements.StatusCode, Namespaces.Protocol);
        code.SetAttribute("Value", status);

        if (!string.IsNullOrEmpty(secondLevelStatus))
        {
            AppendElement(code, "samlp", Elements.StatusCode, Namespaces.Protocol).SetAttribute("Value", secondLevelStatus);
        }

        if (!string.IsNullOrEmpty(message))
        {
            AppendElement(element, "samlp", Elements.StatusMessage, Namespaces.Protocol, message);
        }

        if (signed)
        {
            SignElement(response, issuer, OpenIddictServerSamlService.GetSigningCertificate(options),
                options.SignatureAlgorithm, options.DigestAlgorithm);
        }

        return document.OuterXml;
    }

    private DecodedMessage DecodeRedirectMessage(string? query, string parameter)
    {
        var options = _options.CurrentValue;

        var parameters = ParseRedirectQueryString(query);
        if (parameters is null)
        {
            return new DecodedMessage { Error = SR.ID2259 };
        }

        parameters.TryGetValue(Parameters.RelayState, out var state);
        var relayState = parameters.ContainsKey(Parameters.RelayState) ? state.Value : null;

        if (!parameters.TryGetValue(parameter, out var message) || string.IsNullOrEmpty(message.Value))
        {
            return new DecodedMessage { Error = SR.ID2511, RelayState = relayState };
        }

        if (message.Value.Length > options.MaximumMessageSize * 2)
        {
            return new DecodedMessage { Error = SR.ID2247, RelayState = relayState };
        }

        if (DecodeBase64(message.Value) is not byte[] compressed)
        {
            return new DecodedMessage { Error = SR.ID2246, RelayState = relayState };
        }

        var data = Inflate(compressed, options.MaximumMessageSize, out bool tooLarge);
        if (data is null)
        {
            return new DecodedMessage { Error = tooLarge ? SR.ID2247 : SR.ID2246, RelayState = relayState };
        }

        if (LoadDocument(data, options.MaximumMessageSize, out bool containsDocumentType) is not XmlDocument document)
        {
            return new DecodedMessage { Error = containsDocumentType ? SR.ID2248 : SR.ID2246, RelayState = relayState };
        }

        var decoded = new DecodedMessage { Binding = Bindings.HttpRedirect, Document = document, RelayState = relayState };

        if (parameters.TryGetValue(Parameters.Signature, out var signature))
        {
            if (!parameters.TryGetValue(Parameters.SignatureAlgorithm, out var algorithm))
            {
                decoded.HasInvalidSignatureParameters = true;
            }

            else
            {
                // Note: the signed octets are built from the raw values, as received (SAML bindings, 3.4.4.1).
                var builder = new StringBuilder().Append(parameter).Append('=').Append(message.Raw);

                if (parameters.ContainsKey(Parameters.RelayState))
                {
                    builder.Append('&').Append(Parameters.RelayState).Append('=').Append(state.Raw);
                }

                builder.Append('&').Append(Parameters.SignatureAlgorithm).Append('=').Append(algorithm.Raw);

                decoded.RedirectSignature = (builder.ToString(), algorithm.Value, signature.Value);
            }
        }

        return decoded;
    }

    private DecodedMessage DecodePostMessage(string? message, string? relayState)
    {
        var options = _options.CurrentValue;

        if (string.IsNullOrEmpty(message))
        {
            return new DecodedMessage { Error = SR.ID2511, RelayState = relayState };
        }

        if (message.Length > options.MaximumMessageSize * 2)
        {
            return new DecodedMessage { Error = SR.ID2247, RelayState = relayState };
        }

        if (DecodeBase64(message) is not byte[] data || data.Length is 0)
        {
            return new DecodedMessage { Error = SR.ID2246, RelayState = relayState };
        }

        if (data.Length > options.MaximumMessageSize)
        {
            return new DecodedMessage { Error = SR.ID2247, RelayState = relayState };
        }

        if (LoadDocument(data, options.MaximumMessageSize, out bool containsDocumentType) is not XmlDocument document)
        {
            return new DecodedMessage { Error = containsDocumentType ? SR.ID2248 : SR.ID2246, RelayState = relayState };
        }

        return new DecodedMessage { Binding = Bindings.HttpPost, Document = document, RelayState = relayState };
    }

    private async ValueTask<(OpenIddictServerSamlServiceProvider? Provider, string? Error)> ValidateCommonAsync(
        DecodedMessage message, XmlElement root, DateTimeOffset instant, Uri endpoint, CancellationToken cancellationToken)
    {
        var options = _options.CurrentValue;

        var issuers = GetChildElements(root, Elements.Issuer, Namespaces.Assertion);
        if (issuers.Count is not 1 || GetTextContent(issuers[0]) is not { Length: > 0 } issuer ||
            await _service.FindServiceProviderAsync(issuer, cancellationToken) is not { } provider)
        {
            return (null, SR.ID2502);
        }

        // Validate the signature before using any other value of the message. Logout messages sent using front-channel
        // bindings must be signed (SAML profiles, 4.4.4.1 and 4.4.4.2), as their integrity isn't protected by the binding.
        var result = message switch
        {
            { HasInvalidSignatureParameters: true } => SignatureValidationResult.Invalid,

            { RedirectSignature: var (octets, algorithm, signature) }
                => ValidateRedirectSignature(octets, algorithm, signature, provider.SigningCertificates),

            { Binding: Bindings.HttpPost } => ValidateRootSignature(root, provider.SigningCertificates),

            _ => SignatureValidationResult.Missing
        };

        switch (result)
        {
            case SignatureValidationResult.Missing:              return (provider, SR.ID2503);
            case SignatureValidationResult.Invalid:              return (provider, SR.ID2504);
            case SignatureValidationResult.UnsupportedAlgorithm: return (provider, SR.ID2505);
        }

        var now = options.TimeProvider.GetUtcNow();
        if (instant > now + options.ClockSkew || instant < now - options.AuthenticationRequestLifetime - options.ClockSkew)
        {
            return (provider, SR.ID2506);
        }

        // Note: signed messages must specify their destination (SAML bindings, 3.4.5.2 and 3.5.5.2).
        if (!root.HasAttribute("Destination") || !IsSameUrl(root.GetAttribute("Destination"), endpoint))
        {
            return (provider, SR.ID2507);
        }

        return (provider, null);
    }

    private async ValueTask<LogoutRequestResult> ValidateRequestAsync(DecodedMessage message, Uri endpoint, CancellationToken cancellationToken)
    {
        if (message.Error is string error)
        {
            return RejectRequest(error, relayState: message.RelayState);
        }

        var options = _options.CurrentValue;
        var root = message.Document!.DocumentElement!;

        if (!IsElement(root, Elements.LogoutRequest, Namespaces.Protocol) ||
            !string.Equals(root.GetAttribute("Version"), "2.0", StringComparison.Ordinal) ||
            root.GetAttribute("ID") is not { Length: > 0 } identifier || !IsNCName(identifier) ||
            !TryParseInstant(root.GetAttribute("IssueInstant"), out var instant))
        {
            return RejectRequest(SR.ID2500, relayState: message.RelayState);
        }

        var (provider, failure) = await ValidateCommonAsync(message, root, instant, endpoint, cancellationToken);
        if (provider is null)
        {
            return RejectRequest(failure!, relayState: message.RelayState);
        }

        // Note: an error response can only be returned when the signature is valid and a single logout service is registered.
        if (failure is SR.ID2503 or SR.ID2504 or SR.ID2505)
        {
            return RejectRequest(failure, provider, message.RelayState);
        }

        if (provider.SingleLogoutServiceUrl is null)
        {
            return RejectRequest(SR.ID2510, provider, message.RelayState);
        }

        if (failure is not null)
        {
            return RejectRequest(failure, provider, message.RelayState, identifier, message.Binding, returnable: true);
        }

        DateTimeOffset? expiration = null;

        if (root.HasAttribute("NotOnOrAfter"))
        {
            if (!TryParseInstant(root.GetAttribute("NotOnOrAfter"), out var value))
            {
                return RejectRequest(SR.ID2500, provider, message.RelayState, identifier, message.Binding, returnable: true);
            }

            if (options.TimeProvider.GetUtcNow() - options.ClockSkew >= value)
            {
                return RejectRequest(SR.ID2506, provider, message.RelayState, identifier, message.Binding, returnable: true);
            }

            expiration = value;
        }

        // Note: only unencrypted NameID identifiers are supported (BaseID and EncryptedID are rejected).
        if (GetChildElements(root, "BaseID", Namespaces.Assertion).Count is not 0 ||
            GetChildElements(root, "EncryptedID", Namespaces.Assertion).Count is not 0 ||
            GetChildElements(root, Elements.NameId, Namespaces.Assertion) is not [XmlElement name] ||
            GetTextContent(name) is not { Length: > 0 } nameId)
        {
            return RejectRequest(SR.ID2508, provider, message.RelayState, identifier, message.Binding, returnable: true,
                status: StatusCodes.Requester, secondLevelStatus: StatusCodes.UnknownPrincipal);
        }

        List<string> indexes = [];

        foreach (var element in GetChildElements(root, Elements.SessionIndex, Namespaces.Protocol))
        {
            if (GetTextContent(element) is not { Length: > 0 } index)
            {
                return RejectRequest(SR.ID2500, provider, message.RelayState, identifier, message.Binding, returnable: true);
            }

            indexes.Add(index);
        }

        // Reject replayed logout requests while they are considered fresh (message identifiers are unique per SAML core, 1.3.4).
        if (options.EnableRequestReplayProtection && !await _replayCache.TryAddAsync(
            "logout-request:" + provider.EntityId + "\n" + identifier,
            instant + options.AuthenticationRequestLifetime + options.ClockSkew, cancellationToken))
        {
            _logger.LogInformation(6643, SR.GetResourceString(SR.ID6643), SR.GetResourceString(SR.ID2509));

            return RejectRequest(SR.ID2509, provider, message.RelayState, identifier, message.Binding, returnable: true);
        }

        return new LogoutRequestResult
        {
            Binding = message.Binding,
            CanReturnErrorToServiceProvider = true,
            RelayState = message.RelayState,
            Request = new LogoutRequest
            {
                Binding = message.Binding!,
                Destination = root.GetAttribute("Destination"),
                Id = identifier,
                IssueInstant = instant,
                Issuer = provider.EntityId!,
                NameId = nameId,
                NameIdFormat = name.HasAttribute("Format") ? name.GetAttribute("Format") : null,
                NotOnOrAfter = expiration,
                Reason = root.HasAttribute("Reason") ? root.GetAttribute("Reason") : null,
                SessionIndexes = indexes
            },
            RequestId = identifier,
            ServiceProvider = provider
        };
    }

    private async ValueTask<LogoutResponseResult> ValidateResponseAsync(DecodedMessage message, Uri endpoint, CancellationToken cancellationToken)
    {
        if (message.Error is string error)
        {
            return RejectResponse(error, message.RelayState);
        }

        var root = message.Document!.DocumentElement!;

        if (!IsElement(root, Elements.LogoutResponse, Namespaces.Protocol) ||
            !string.Equals(root.GetAttribute("Version"), "2.0", StringComparison.Ordinal) ||
            root.GetAttribute("ID") is not { Length: > 0 } identifier || !IsNCName(identifier) ||
            root.GetAttribute("InResponseTo") is not { Length: > 0 } inResponseTo || !IsNCName(inResponseTo) ||
            !TryParseInstant(root.GetAttribute("IssueInstant"), out var instant))
        {
            return RejectResponse(SR.ID2501, message.RelayState);
        }

        var (provider, failure) = await ValidateCommonAsync(message, root, instant, endpoint, cancellationToken);
        if (failure is not null)
        {
            return RejectResponse(failure, message.RelayState);
        }

        var (status, secondLevelStatus) = GetStatus(root);
        if (string.IsNullOrEmpty(status))
        {
            return RejectResponse(SR.ID2501, message.RelayState);
        }

        return new LogoutResponseResult
        {
            Id = identifier,
            InResponseTo = inResponseTo,
            RelayState = message.RelayState,
            SecondLevelStatus = secondLevelStatus,
            ServiceProvider = provider,
            Status = status
        };
    }

    private LogoutRequestResult RejectRequest(string description, OpenIddictServerSamlServiceProvider? provider = null,
        string? relayState = null, string? identifier = null, string? binding = null, bool returnable = false,
        string status = StatusCodes.Requester, string? secondLevelStatus = null)
    {
        var message = SR.GetResourceString(description);

        _logger.LogInformation(6801, SR.GetResourceString(SR.ID6801), message);

        return new LogoutRequestResult
        {
            Binding = binding,
            CanReturnErrorToServiceProvider = returnable && provider?.SingleLogoutServiceUrl is not null,
            ErrorDescription = message,
            RelayState = relayState,
            RequestId = identifier,
            SecondLevelStatus = secondLevelStatus,
            ServiceProvider = provider,
            Status = status
        };
    }

    private LogoutResponseResult RejectResponse(string description, string? relayState)
    {
        var message = SR.GetResourceString(description);

        _logger.LogInformation(6801, SR.GetResourceString(SR.ID6801), message);

        return new LogoutResponseResult { ErrorDescription = message, RelayState = relayState };
    }

    private void EnsureEnabled()
    {
        if (!_options.CurrentValue.EnableSingleLogout)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID01002));
        }
    }

    private OpenIddictServerOptions GetServerOptions()
    {
        var options = _provider.GetService<IOptionsMonitor<OpenIddictServerOptions>>()?.CurrentValue;
        if (options is null || options.EnableDegradedMode)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID01001));
        }

        return options;
    }

    private IOpenIddictSessionManager GetSessionManager()
        => _provider.GetService<IOpenIddictSessionManager>() ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID01001));

    private string? GetLoginId(ClaimsPrincipal? principal)
        => _options.CurrentValue.LoginIdClaimType is { Length: > 0 } type ? principal?.FindFirst(type)?.Value : null;

    private static string? GetSubject(ClaimsPrincipal? principal)
        => principal?.FindFirst(Claims.Subject)?.Value is { Length: > 0 } subject ? subject :
           principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value is { Length: > 0 } identifier ? identifier : null;

    private static string GetFrontchannelBinding(OpenIddictServerSamlServiceProvider provider, string? fallback)
        => provider.SingleLogoutServiceBinding switch
        {
            Bindings.HttpPost => Bindings.HttpPost,
            Bindings.HttpRedirect or null => Bindings.HttpRedirect,

            // Note: when the service provider uses the SOAP binding, the logout response is returned using the binding
            // used to send the request, as a front-channel response is expected by the user agent (SAML profiles, 4.4.4.2).
            _ => fallback is Bindings.HttpPost ? Bindings.HttpPost : Bindings.HttpRedirect
        };

    private static (string? Status, string? SecondLevelStatus) GetStatus(XmlElement response)
    {
        if (GetChildElements(response, Elements.Status, Namespaces.Protocol) is not [XmlElement status] ||
            GetChildElements(status, Elements.StatusCode, Namespaces.Protocol) is not [XmlElement code] ||
            code.GetAttribute("Value") is not { Length: > 0 } value)
        {
            return (null, null);
        }

        return (value, GetChildElements(code, Elements.StatusCode, Namespaces.Protocol) is [XmlElement child] &&
            child.GetAttribute("Value") is { Length: > 0 } second ? second : null);
    }

    private static bool IsElement(XmlElement element, string name, string ns)
        => string.Equals(element.LocalName, name, StringComparison.Ordinal) &&
           string.Equals(element.NamespaceURI, ns, StringComparison.Ordinal);

    private static string? GetProperty(ImmutableDictionary<string, JsonElement> properties, string name)
        => properties.TryGetValue(name, out var value) && value.ValueKind is JsonValueKind.String ? value.GetString() : null;

    private static JsonElement CreateJsonString(string value)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStringValue(value);
        }

        using var document = JsonDocument.Parse(stream.ToArray());
        return document.RootElement.Clone();
    }

    private static string SerializeState(LogoutState state)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(StateVersion);
            WriteNullable(writer, state.InitiatorServiceProvider);
            WriteNullable(writer, state.InitiatorRequestId);
            WriteNullable(writer, state.InitiatorBinding);
            WriteNullable(writer, state.RelayState);
            WriteNullable(writer, state.ReturnUrl);
            writer.Write(state.PartialLogout);
            writer.Write(state.Pending.Count);

            foreach (var participant in state.Pending)
            {
                writer.Write(participant.ServiceProvider);
                writer.Write(participant.SessionId);
                writer.Write(participant.NameId);
                WriteNullable(writer, participant.NameIdFormat);
                writer.Write(participant.Binding);
                writer.Write(participant.Url.AbsoluteUri);
            }
        }

        return Convert.ToBase64String(stream.ToArray());

        static void WriteNullable(BinaryWriter writer, string? value)
        {
            writer.Write(value is not null);
            if (value is not null)
            {
                writer.Write(value);
            }
        }
    }

    private static LogoutState? DeserializeState(string value)
    {
        try
        {
            using var stream = new MemoryStream(Convert.FromBase64String(value), writable: false);
            using var reader = new BinaryReader(stream, Encoding.UTF8);

            if (reader.ReadByte() is not StateVersion)
            {
                return null;
            }

            var state = new LogoutState
            {
                InitiatorServiceProvider = ReadNullable(reader),
                InitiatorRequestId = ReadNullable(reader),
                InitiatorBinding = ReadNullable(reader),
                RelayState = ReadNullable(reader),
                ReturnUrl = ReadNullable(reader),
                PartialLogout = reader.ReadBoolean()
            };

            var count = reader.ReadInt32();
            if (count < 0 || count > 1_000)
            {
                return null;
            }

            for (var index = 0; index < count; index++)
            {
                state.Pending.Add(new LogoutParticipant
                {
                    ServiceProvider = reader.ReadString(),
                    SessionId = reader.ReadString(),
                    NameId = reader.ReadString(),
                    NameIdFormat = ReadNullable(reader),
                    Binding = reader.ReadString(),
                    Url = new Uri(reader.ReadString(), UriKind.Absolute)
                });
            }

            return stream.Position == stream.Length ? state : null;
        }

        catch (Exception exception) when (exception is ArgumentException or EndOfStreamException or FormatException or IOException)
        {
            return null;
        }

        static string? ReadNullable(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;
    }

    private sealed class DecodedMessage
    {
        public string? Binding { get; init; }

        public XmlDocument? Document { get; init; }

        public string? Error { get; init; }

        public bool HasInvalidSignatureParameters { get; set; }

        public (string Octets, string Algorithm, string Signature)? RedirectSignature { get; set; }

        public string? RelayState { get; init; }
    }

    private sealed class LogoutState
    {
        public string? InitiatorBinding { get; init; }

        public string? InitiatorRequestId { get; init; }

        public string? InitiatorServiceProvider { get; init; }

        public bool PartialLogout { get; set; }

        public List<LogoutParticipant> Pending { get; } = [];

        public List<Uri> FrontchannelLogoutUris { get; } = [];

        public string? RelayState { get; init; }

        public string? ReturnUrl { get; init; }
    }

    /// <summary>
    /// Represents the state shared by the session terminations dispatched by the SAML single logout service.
    /// </summary>
    internal sealed class TerminationState
    {
        public List<LogoutParticipant> FrontchannelParticipants { get; } = [];

        public bool PartialLogout { get; set; }
    }
}
