/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server.AspNetCore.AdminUI.Components.Pages;
using static OpenIddict.Server.AspNetCore.AdminUI.OpenIddictServerAspNetCoreAdminUIConstants;
using Operations = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreAdminOperations;

namespace OpenIddict.Server.AspNetCore.AdminUI;

/// <summary>
/// Contains the request delegates of the OpenIddict admin UI pages.
/// </summary>
internal sealed class OpenIddictServerAspNetCoreAdminUIEndpoints
{
    private const string ContentSecurityPolicy =
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

    private const int MaximumSearchScannedApplications = 1_000;

    private const string StylesheetResourceName = "OpenIddict.Server.AspNetCore.AdminUI.openiddict-admin.css";

    private readonly string _prefix;

    public OpenIddictServerAspNetCoreAdminUIEndpoints(string prefix)
    {
        ArgumentNullException.ThrowIfNull(prefix);

        // Note: the prefix is used to generate the links rendered in the pages and is expected to be a literal path.
        _prefix = prefix.Trim('/') is { Length: > 0 } value ? "/" + value : string.Empty;
    }

    public Task Home(HttpContext context) => ExecuteAsync(context, context =>
        Task.FromResult<IResult>(TypedResults.Redirect(GetBasePath(context) + "/" + Paths.Applications)));

    public static async Task StylesheetAsync(HttpContext context)
    {
        using var stream = typeof(OpenIddictServerAspNetCoreAdminUIEndpoints).Assembly.GetManifestResourceStream(StylesheetResourceName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0683));

        context.Response.ContentType = "text/css; charset=utf-8";
        context.Response.Headers.CacheControl = "private, max-age=3600";
        context.Response.Headers.XContentTypeOptions = "nosniff";

        await stream.CopyToAsync(context.Response.Body, context.RequestAborted);
    }

    public Task ListApplicationsAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);
        var (page, size, offset) = GetPagination(context);
        var search = GetQuery(context, QueryStringParameters.Search);

        List<(string Id, OpenIddictApplicationDescriptor Descriptor)> items = [];
        var next = false;
        var truncated = false;

        // Note: the application stores don't support searching by client identifier or display name
        // using the untyped managers: when a search term is specified, the entries are filtered in memory.
        // To bound the work done per request, at most MaximumSearchScannedApplications entries are inspected.
        var applications = search is null ?
            manager.ListAsync(size + 1, offset, context.RequestAborted) :
            manager.ListAsync(MaximumSearchScannedApplications + 1, offset: 0, context.RequestAborted);

        var skipped = 0;
        var scanned = 0;

        await foreach (var application in applications.WithCancellation(context.RequestAborted))
        {
            if (search is not null)
            {
                if (++scanned > MaximumSearchScannedApplications)
                {
                    truncated = true;
                    break;
                }

                if (!Matches(await manager.GetClientIdAsync(application, context.RequestAborted), search) &&
                    !Matches(await manager.GetDisplayNameAsync(application, context.RequestAborted), search) &&
                    !Matches(await manager.GetIdAsync(application, context.RequestAborted), search))
                {
                    continue;
                }

                if (skipped++ < offset)
                {
                    continue;
                }
            }

            if (items.Count == size)
            {
                next = true;
                break;
            }

            var (identifier, descriptor) = await Operations.DescribeApplicationAsync(manager, application, context.RequestAborted);
            descriptor.ClientSecret = null;

            items.Add((identifier ?? string.Empty, descriptor));
        }

        // If the search was truncated, ensure an application whose client identifier exactly
        // matches the search term is always displayed on the first page, even if it wasn't scanned.
        if (truncated && page is 1 && await manager.FindByClientIdAsync(search!, context.RequestAborted) is object match)
        {
            var (identifier, descriptor) = await Operations.DescribeApplicationAsync(manager, match, context.RequestAborted);
            descriptor.ClientSecret = null;

            if (!items.Exists(item => string.Equals(item.Id, identifier, StringComparison.Ordinal)))
            {
                items.Insert(0, (identifier ?? string.Empty, descriptor));
            }
        }

        return Page<ApplicationListPage>(context, new()
        {
            [nameof(ApplicationListPage.Items)] = items,
            [nameof(ApplicationListPage.Search)] = search,
            [nameof(ApplicationListPage.PageNumber)] = page,
            [nameof(ApplicationListPage.HasNextPage)] = next,
            [nameof(ApplicationListPage.SearchLimit)] = truncated ? MaximumSearchScannedApplications : null,
            [nameof(ApplicationListPage.Notice)] = GetQuery(context, QueryStringParameters.Notice)
        });

        static bool Matches(string? value, string search)
            => value is not null && value.Contains(search, StringComparison.OrdinalIgnoreCase);
    });

    public Task NewApplicationAsync(HttpContext context) => ExecuteAsync(context, context =>
    {
        GetManager<IOpenIddictApplicationManager>(context);

        return Task.FromResult(ApplicationEditor(context, StatusCodes.Status200OK, identifier: null,
            new OpenIddictApplicationDescriptor(), hasClientSecret: false, errors: []));
    });

    public Task CreateApplicationAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);
        var form = await ReadFormAsync(context);

        var descriptor = new OpenIddictApplicationDescriptor();
        var errors = OpenIddictServerAspNetCoreAdminUIForms.ReadApplication(form, descriptor);

        string? secret = null;

        var mode = OpenIddictServerAspNetCoreAdminUIForms.GetString(form, FormFields.Mode);
        switch (mode)
        {
            case null or SecretModes.Remove:
                break;

            case SecretModes.Generate:
                descriptor.ClientSecret = secret = GenerateClientSecret();
                break;

            case SecretModes.Set when OpenIddictServerAspNetCoreAdminUIForms.GetString(form, FormFields.ClientSecret) is string value:
                descriptor.ClientSecret = value;
                break;

            default:
                errors.Add(SR.FormatID2341(FormFields.ClientSecret));
                break;
        }

        if (errors is [_, ..])
        {
            descriptor.ClientSecret = null;
            return ApplicationEditor(context, StatusCodes.Status400BadRequest, identifier: null, descriptor, hasClientSecret: false, errors);
        }

        object application;

        try
        {
            application = await manager.CreateAsync(descriptor, context.RequestAborted);
        }

        catch (OpenIddictExceptions.ValidationException exception)
        {
            descriptor.ClientSecret = null;
            return ApplicationEditor(context, StatusCodes.Status400BadRequest, identifier: null,
                descriptor, hasClientSecret: false, GetErrors(exception));
        }

        var (identifier, result) = await Operations.DescribeApplicationAsync(manager, application, context.RequestAborted);
        Log(context, 6480, SR.ID6480, "application", identifier);

        if (secret is not null)
        {
            // Note: the generated secret is displayed once and is never included in a redirection URI.
            var hasClientSecret = !string.IsNullOrEmpty(result.ClientSecret);
            result.ClientSecret = null;

            return ApplicationEditor(context, StatusCodes.Status200OK, identifier, result, hasClientSecret,
                errors: [], notice: Notices.Created, secret);
        }

        return TypedResults.Redirect(GetUrl(context, Paths.Applications, identifier, notice: Notices.Created));
    });

    public Task EditApplicationAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object application)
        {
            return NotFound(context);
        }

        var (identifier, descriptor) = await Operations.DescribeApplicationAsync(manager, application, context.RequestAborted);
        var hasClientSecret = !string.IsNullOrEmpty(descriptor.ClientSecret);
        descriptor.ClientSecret = null;

        return ApplicationEditor(context, StatusCodes.Status200OK, identifier, descriptor, hasClientSecret,
            errors: [], GetQuery(context, QueryStringParameters.Notice));
    });

    public Task UpdateApplicationAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);
        var form = await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object application)
        {
            return NotFound(context);
        }

        var (identifier, descriptor) = await Operations.DescribeApplicationAsync(manager, application, context.RequestAborted);
        var hasClientSecret = !string.IsNullOrEmpty(descriptor.ClientSecret);

        // Note: the descriptor still contains the stored client secret, that is left unchanged by the form.
        var errors = OpenIddictServerAspNetCoreAdminUIForms.ReadApplication(form, descriptor);
        if (errors is [_, ..])
        {
            descriptor.ClientSecret = null;
            return ApplicationEditor(context, StatusCodes.Status400BadRequest, identifier, descriptor, hasClientSecret, errors);
        }

        try
        {
            await manager.UpdateAsync(application, descriptor, context.RequestAborted);
        }

        catch (OpenIddictExceptions.ValidationException exception)
        {
            descriptor.ClientSecret = null;
            return ApplicationEditor(context, StatusCodes.Status400BadRequest, identifier, descriptor, hasClientSecret, GetErrors(exception));
        }

        catch (OpenIddictExceptions.ConcurrencyException)
        {
            descriptor.ClientSecret = null;
            return ApplicationEditor(context, StatusCodes.Status409Conflict, identifier, descriptor, hasClientSecret,
                [SR.GetResourceString(SR.ID2244)]);
        }

        Log(context, 6481, SR.ID6481, "application", identifier);

        return TypedResults.Redirect(GetUrl(context, Paths.Applications, identifier, notice: Notices.Updated));
    });

    public Task ChangeApplicationSecretAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);
        var form = await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object application)
        {
            return NotFound(context);
        }

        var (identifier, descriptor) = await Operations.DescribeApplicationAsync(manager, application, context.RequestAborted);
        var hasClientSecret = !string.IsNullOrEmpty(descriptor.ClientSecret);

        string? secret = null;

        switch (OpenIddictServerAspNetCoreAdminUIForms.GetString(form, FormFields.Mode))
        {
            case SecretModes.Generate:
                descriptor.ClientSecret = secret = GenerateClientSecret();
                break;

            case SecretModes.Set when OpenIddictServerAspNetCoreAdminUIForms.GetString(form, FormFields.ClientSecret) is string value:
                descriptor.ClientSecret = value;
                break;

            case SecretModes.Remove:
                descriptor.ClientSecret = null;
                break;

            default:
                descriptor.ClientSecret = null;
                return ApplicationEditor(context, StatusCodes.Status400BadRequest, identifier, descriptor, hasClientSecret,
                    [SR.FormatID2341(FormFields.ClientSecret)]);
        }

        try
        {
            // Note: the manager automatically hashes the new client secret before storing it.
            await manager.UpdateAsync(application, descriptor, context.RequestAborted);
        }

        catch (OpenIddictExceptions.ValidationException exception)
        {
            descriptor.ClientSecret = null;
            return ApplicationEditor(context, StatusCodes.Status400BadRequest, identifier, descriptor, hasClientSecret, GetErrors(exception));
        }

        catch (OpenIddictExceptions.ConcurrencyException)
        {
            descriptor.ClientSecret = null;
            return ApplicationEditor(context, StatusCodes.Status409Conflict, identifier, descriptor, hasClientSecret,
                [SR.GetResourceString(SR.ID2244)]);
        }

        Log(context, 6484, SR.ID6484, identifier);

        if (secret is not null)
        {
            descriptor.ClientSecret = null;

            // Note: the generated secret is displayed once and is never included in a redirection URI.
            return ApplicationEditor(context, StatusCodes.Status200OK, identifier, descriptor, hasClientSecret: true,
                errors: [], notice: Notices.Updated, secret);
        }

        return TypedResults.Redirect(GetUrl(context, Paths.Applications, identifier, notice: Notices.Updated));
    });

    public Task DeleteApplicationAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);
        await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object application)
        {
            return NotFound(context);
        }

        var identifier = await manager.GetIdAsync(application, context.RequestAborted);

        try
        {
            await manager.DeleteAsync(application, context.RequestAborted);
        }

        catch (OpenIddictExceptions.ConcurrencyException)
        {
            return Message(context, StatusCodes.Status409Conflict, SR.GetResourceString(SR.ID2244));
        }

        Log(context, 6482, SR.ID6482, "application", identifier);

        return TypedResults.Redirect(GetUrl(context, Paths.Applications, identifier: null, notice: Notices.Deleted));
    });

    public Task ListScopesAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);
        var (page, size, offset) = GetPagination(context);

        List<(string Id, OpenIddictScopeDescriptor Descriptor)> items = [];
        var next = false;

        await foreach (var scope in manager.ListAsync(size + 1, offset, context.RequestAborted))
        {
            if (items.Count == size)
            {
                next = true;
                break;
            }

            var (identifier, descriptor) = await Operations.DescribeScopeAsync(manager, scope, context.RequestAborted);
            items.Add((identifier ?? string.Empty, descriptor));
        }

        return Page<ScopeListPage>(context, new()
        {
            [nameof(ScopeListPage.Items)] = items,
            [nameof(ScopeListPage.PageNumber)] = page,
            [nameof(ScopeListPage.HasNextPage)] = next,
            [nameof(ScopeListPage.Notice)] = GetQuery(context, QueryStringParameters.Notice)
        });
    });

    public Task NewScopeAsync(HttpContext context) => ExecuteAsync(context, context =>
    {
        GetManager<IOpenIddictScopeManager>(context);

        return Task.FromResult(ScopeEditor(context, StatusCodes.Status200OK, identifier: null, new OpenIddictScopeDescriptor(), errors: []));
    });

    public Task CreateScopeAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);
        var form = await ReadFormAsync(context);

        var descriptor = new OpenIddictScopeDescriptor();
        var errors = OpenIddictServerAspNetCoreAdminUIForms.ReadScope(form, descriptor);
        if (errors is [_, ..])
        {
            return ScopeEditor(context, StatusCodes.Status400BadRequest, identifier: null, descriptor, errors);
        }

        object scope;

        try
        {
            scope = await manager.CreateAsync(descriptor, context.RequestAborted);
        }

        catch (OpenIddictExceptions.ValidationException exception)
        {
            return ScopeEditor(context, StatusCodes.Status400BadRequest, identifier: null, descriptor, GetErrors(exception));
        }

        var identifier = await manager.GetIdAsync(scope, context.RequestAborted);
        Log(context, 6480, SR.ID6480, "scope", identifier);

        return TypedResults.Redirect(GetUrl(context, Paths.Scopes, identifier, notice: Notices.Created));
    });

    public Task EditScopeAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object scope)
        {
            return NotFound(context);
        }

        var (identifier, descriptor) = await Operations.DescribeScopeAsync(manager, scope, context.RequestAborted);

        return ScopeEditor(context, StatusCodes.Status200OK, identifier, descriptor, errors: [],
            GetQuery(context, QueryStringParameters.Notice));
    });

    public Task UpdateScopeAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);
        var form = await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object scope)
        {
            return NotFound(context);
        }

        var (identifier, descriptor) = await Operations.DescribeScopeAsync(manager, scope, context.RequestAborted);

        var errors = OpenIddictServerAspNetCoreAdminUIForms.ReadScope(form, descriptor);
        if (errors is [_, ..])
        {
            return ScopeEditor(context, StatusCodes.Status400BadRequest, identifier, descriptor, errors);
        }

        try
        {
            await manager.UpdateAsync(scope, descriptor, context.RequestAborted);
        }

        catch (OpenIddictExceptions.ValidationException exception)
        {
            return ScopeEditor(context, StatusCodes.Status400BadRequest, identifier, descriptor, GetErrors(exception));
        }

        catch (OpenIddictExceptions.ConcurrencyException)
        {
            return ScopeEditor(context, StatusCodes.Status409Conflict, identifier, descriptor, [SR.GetResourceString(SR.ID2244)]);
        }

        Log(context, 6481, SR.ID6481, "scope", identifier);

        return TypedResults.Redirect(GetUrl(context, Paths.Scopes, identifier, notice: Notices.Updated));
    });

    public Task DeleteScopeAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);
        await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object scope)
        {
            return NotFound(context);
        }

        var identifier = await manager.GetIdAsync(scope, context.RequestAborted);

        try
        {
            await manager.DeleteAsync(scope, context.RequestAborted);
        }

        catch (OpenIddictExceptions.ConcurrencyException)
        {
            return Message(context, StatusCodes.Status409Conflict, SR.GetResourceString(SR.ID2244));
        }

        Log(context, 6482, SR.ID6482, "scope", identifier);

        return TypedResults.Redirect(GetUrl(context, Paths.Scopes, identifier: null, notice: Notices.Deleted));
    });

    public Task ListAuthorizationsAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);
        var applications = GetManager<IOpenIddictApplicationManager>(context);
        var (page, size, offset) = GetPagination(context);

        var subject = GetQuery(context, QueryStringParameters.Subject);
        var client = GetQuery(context, QueryStringParameters.Client);
        var status = GetQuery(context, QueryStringParameters.Status);
        var type = GetQuery(context, QueryStringParameters.Type);

        List<(string Id, OpenIddictAuthorizationDescriptor Descriptor)> items = [];
        var next = false;

        var (found, application) = await ResolveApplicationIdAsync(applications, client, context.RequestAborted);
        if (found)
        {
            await foreach (var authorization in Operations.ListAuthorizationsAsync(manager,
                subject, application, status, type, size + 1, offset, context.RequestAborted))
            {
                if (items.Count == size)
                {
                    next = true;
                    break;
                }

                var (identifier, descriptor) = await Operations.DescribeAuthorizationAsync(manager, authorization, context.RequestAborted);
                items.Add((identifier ?? string.Empty, descriptor));
            }
        }

        return Page<AuthorizationListPage>(context, new()
        {
            [nameof(AuthorizationListPage.Items)] = items,
            [nameof(AuthorizationListPage.ClientIds)] = await ResolveClientIdsAsync(applications,
                items.Select(static item => item.Descriptor.ApplicationId), context.RequestAborted),
            [nameof(AuthorizationListPage.Subject)] = subject,
            [nameof(AuthorizationListPage.Client)] = client,
            [nameof(AuthorizationListPage.Status)] = status,
            [nameof(AuthorizationListPage.Type)] = type,
            [nameof(AuthorizationListPage.PageNumber)] = page,
            [nameof(AuthorizationListPage.HasNextPage)] = next,
            [nameof(AuthorizationListPage.Notice)] = GetQuery(context, QueryStringParameters.Notice)
        });
    });

    public Task ShowAuthorizationAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object authorization)
        {
            return NotFound(context);
        }

        return await AuthorizationDetailsAsync(context, StatusCodes.Status200OK, manager, authorization, errors: [],
            GetQuery(context, QueryStringParameters.Notice));
    });

    public Task RevokeAuthorizationAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);
        await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object authorization)
        {
            return NotFound(context);
        }

        // Note: the tokens attached to the authorization are also revoked.
        if (!await Operations.TryRevokeAuthorizationAsync(manager,
            context.RequestServices.GetService<IOpenIddictTokenManager>(), authorization, context.RequestAborted))
        {
            return await AuthorizationDetailsAsync(context, StatusCodes.Status409Conflict, manager, authorization,
                [SR.GetResourceString(SR.ID2244)]);
        }

        var identifier = await manager.GetIdAsync(authorization, context.RequestAborted);
        Log(context, 6483, SR.ID6483, "authorization", identifier);

        return TypedResults.Redirect(GetUrl(context, Paths.Authorizations, identifier, notice: Notices.Revoked));
    });

    public Task ListTokensAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictTokenManager>(context);
        var applications = GetManager<IOpenIddictApplicationManager>(context);
        var (page, size, offset) = GetPagination(context);

        var subject = GetQuery(context, QueryStringParameters.Subject);
        var client = GetQuery(context, QueryStringParameters.Client);
        var status = GetQuery(context, QueryStringParameters.Status);
        var type = GetQuery(context, QueryStringParameters.Type);
        var authorization = GetQuery(context, QueryStringParameters.Authorization);

        List<(string Id, OpenIddictTokenDescriptor Descriptor)> items = [];
        var next = false;

        var (found, application) = await ResolveApplicationIdAsync(applications, client, context.RequestAborted);
        if (found && authorization is null)
        {
            await foreach (var token in Operations.ListTokensAsync(manager,
                subject, application, status, type, size + 1, offset, context.RequestAborted))
            {
                if (items.Count == size)
                {
                    next = true;
                    break;
                }

                items.Add(await DescribeTokenAsync(manager, token, context.RequestAborted));
            }
        }

        // Note: the token stores can't combine the authorization filter with the other filters:
        // when an authorization identifier is specified, the tokens attached to the authorization
        // are retrieved and the other filters (and the pagination) are applied in memory.
        else if (found)
        {
            var skipped = 0;

            await foreach (var token in manager.FindByAuthorizationIdAsync(authorization!, context.RequestAborted))
            {
                var item = await DescribeTokenAsync(manager, token, context.RequestAborted);
                if ((subject is not null && !string.Equals(item.Descriptor.Subject, subject, StringComparison.Ordinal)) ||
                    (application is not null && !string.Equals(item.Descriptor.ApplicationId, application, StringComparison.Ordinal)) ||
                    (status is not null && !string.Equals(item.Descriptor.Status, status, StringComparison.Ordinal)) ||
                    (type is not null && !string.Equals(item.Descriptor.Type, type, StringComparison.Ordinal)))
                {
                    continue;
                }

                if (skipped++ < offset)
                {
                    continue;
                }

                if (items.Count == size)
                {
                    next = true;
                    break;
                }

                items.Add(item);
            }
        }

        return Page<TokenListPage>(context, new()
        {
            [nameof(TokenListPage.Items)] = items,
            [nameof(TokenListPage.ClientIds)] = await ResolveClientIdsAsync(applications,
                items.Select(static item => item.Descriptor.ApplicationId), context.RequestAborted),
            [nameof(TokenListPage.Subject)] = subject,
            [nameof(TokenListPage.Client)] = client,
            [nameof(TokenListPage.Status)] = status,
            [nameof(TokenListPage.Type)] = type,
            [nameof(TokenListPage.Authorization)] = authorization,
            [nameof(TokenListPage.PageNumber)] = page,
            [nameof(TokenListPage.HasNextPage)] = next,
            [nameof(TokenListPage.Notice)] = GetQuery(context, QueryStringParameters.Notice)
        });
    });

    public Task ShowTokenAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictTokenManager>(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object token)
        {
            return NotFound(context);
        }

        return await TokenDetailsAsync(context, StatusCodes.Status200OK, manager, token, errors: [],
            GetQuery(context, QueryStringParameters.Notice));
    });

    public Task RevokeTokenAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictTokenManager>(context);
        await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object token)
        {
            return NotFound(context);
        }

        if (!await manager.TryRevokeAsync(token, context.RequestAborted))
        {
            return await TokenDetailsAsync(context, StatusCodes.Status409Conflict, manager, token,
                [SR.GetResourceString(SR.ID2244)]);
        }

        var identifier = await manager.GetIdAsync(token, context.RequestAborted);
        Log(context, 6483, SR.ID6483, "token", identifier);

        return TypedResults.Redirect(GetUrl(context, Paths.Tokens, identifier, notice: Notices.Revoked));
    });

    public Task ListSessionsAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictSessionManager>(context);
        var applications = GetManager<IOpenIddictApplicationManager>(context);
        var (page, size, offset) = GetPagination(context);

        var subject = GetQuery(context, QueryStringParameters.Subject);
        var client = GetQuery(context, QueryStringParameters.Client);
        var status = GetQuery(context, QueryStringParameters.Status);
        var login = GetQuery(context, QueryStringParameters.LoginId);

        List<(string Id, OpenIddictSessionDescriptor Descriptor)> items = [];
        var next = false;

        var (found, application) = await ResolveApplicationIdAsync(applications, client, context.RequestAborted);
        if (found)
        {
            await foreach (var session in Operations.ListSessionsAsync(manager,
                subject, login, application, status, size + 1, offset, context.RequestAborted))
            {
                if (items.Count == size)
                {
                    next = true;
                    break;
                }

                items.Add(await DescribeSessionAsync(manager, session, context.RequestAborted));
            }
        }

        return Page<SessionListPage>(context, new()
        {
            [nameof(SessionListPage.Items)] = items,
            [nameof(SessionListPage.ClientIds)] = await ResolveClientIdsAsync(applications,
                items.Select(static item => item.Descriptor.ApplicationId), context.RequestAborted),
            [nameof(SessionListPage.Subject)] = subject,
            [nameof(SessionListPage.Client)] = client,
            [nameof(SessionListPage.Status)] = status,
            [nameof(SessionListPage.LoginId)] = login,
            [nameof(SessionListPage.PageNumber)] = page,
            [nameof(SessionListPage.HasNextPage)] = next,
            [nameof(SessionListPage.Notice)] = GetQuery(context, QueryStringParameters.Notice)
        });
    });

    public Task ShowSessionAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictSessionManager>(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object session)
        {
            return NotFound(context);
        }

        return await SessionDetailsAsync(context, StatusCodes.Status200OK, manager, session, errors: [],
            GetQuery(context, QueryStringParameters.Notice));
    });

    public Task TerminateSessionAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictSessionManager>(context);
        await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object session ||
            await manager.GetIdAsync(session, context.RequestAborted) is not { Length: > 0 } identifier)
        {
            return NotFound(context);
        }

        var service = context.RequestServices.GetService<OpenIddictServerService>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID01040));

        OpenIddictServerSessionTerminationResult? result;

        // Note: the session is terminated using the same server service as the admin API, so that the
        // valid sessions sharing its login identifier are also revoked and the client applications that
        // participated in these sessions are notified using back-channel logout, if enabled.
        try
        {
            result = await service.TerminateSessionAsync(identifier, context.RequestAborted);
        }

        // Configuration errors (e.g missing issuer or signing key, degraded mode) are rendered as a server error.
        catch (InvalidOperationException exception)
        {
            return await SessionDetailsAsync(context, StatusCodes.Status500InternalServerError, manager, session, [exception.Message]);
        }

        // Note: the session may have been deleted concurrently.
        if (result is null)
        {
            return NotFound(context);
        }

        Log(context, 6840, SR.ID6840, identifier, result.SessionIds.Length,
            result.NotifiedParticipants.Length, result.FailedParticipants.Length);

        // Note: the result is rendered directly (and not using a redirection) as it can't be represented in a URI.
        // The session is retrieved again to reflect the status updated by the termination.
        session = await FindByIdAsync(manager.FindByIdAsync, identifier, context.RequestAborted) ?? session;

        return await SessionDetailsAsync(context, StatusCodes.Status200OK, manager, session, errors: [],
            result.SessionIds.IsDefaultOrEmpty ? null : Notices.Terminated, result);
    });

    public Task ListKeysAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictKeyManager>(context);

        return await KeyListAsync(context, StatusCodes.Status200OK, manager, errors: [],
            GetQuery(context, QueryStringParameters.Notice));
    });

    public Task RevokeKeyAsync(HttpContext context) => ExecuteAsync(context, async context =>
    {
        var manager = GetManager<IOpenIddictKeyManager>(context);
        await ReadFormAsync(context);

        if (await FindByIdAsync(manager.FindByIdAsync, GetIdentifier(context), context.RequestAborted) is not object key)
        {
            return NotFound(context);
        }

        // Note: the credentials cached by the key ring are discarded so that the revoked key is no longer used.
        if (!await Operations.TryRevokeKeyAsync(manager,
            context.RequestServices.GetService<OpenIddictServerKeyRing>(), key, context.RequestAborted))
        {
            return await KeyListAsync(context, StatusCodes.Status409Conflict, manager, [SR.GetResourceString(SR.ID2244)]);
        }

        Log(context, 6483, SR.ID6483, "key", await manager.GetIdAsync(key, context.RequestAborted));

        return TypedResults.Redirect(GetUrl(context, Paths.Keys, identifier: null, notice: Notices.Revoked));
    });

    private async Task ExecuteAsync(HttpContext context, Func<HttpContext, Task<IResult>> handler)
    {
        var headers = context.Response.Headers;
        headers.CacheControl = "no-store";
        headers.Pragma = "no-cache";
        headers.ContentSecurityPolicy = ContentSecurityPolicy;
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "no-referrer";

        IResult result;

        try
        {
            result = await handler(context);
        }

        catch (AntiforgeryValidationException)
        {
            result = Message(context, StatusCodes.Status400BadRequest, SR.GetResourceString(SR.ID2340));
        }

        await result.ExecuteAsync(context);
    }

    private static async Task<IFormCollection> ReadFormAsync(HttpContext context)
    {
        // Note: the antiforgery token is validated independently of whether the
        // antiforgery middleware was registered (it only validates endpoints
        // declaring antiforgery metadata, which the admin UI endpoints don't).
        await context.RequestServices.GetRequiredService<IAntiforgery>().ValidateRequestAsync(context);

        return await context.Request.ReadFormAsync(context.RequestAborted);
    }

    private static TManager GetManager<TManager>(HttpContext context) where TManager : notnull
        => context.RequestServices.GetService<TManager>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0680));

    private static string GetIdentifier(HttpContext context)
        => context.Request.RouteValues["id"] as string ?? string.Empty;

    private static string? GetQuery(HttpContext context, string name)
        => ((string?) context.Request.Query[name])?.Trim() is { Length: > 0 } value ? value : null;

    private static (int Page, int Size, int Offset) GetPagination(HttpContext context)
    {
        var size = context.RequestServices.GetRequiredService<IOptions<OpenIddictServerAspNetCoreAdminUIOptions>>().Value.PageSize;

        if (!int.TryParse(GetQuery(context, QueryStringParameters.Page), NumberStyles.None, CultureInfo.InvariantCulture, out var page) ||
            page < 1 || (long) (page - 1) * size > int.MaxValue - size - 1)
        {
            page = 1;
        }

        return (page, size, (page - 1) * size);
    }

    private string GetBasePath(HttpContext context) => context.Request.PathBase.Value + _prefix;

    private string GetUrl(HttpContext context, string section, string? identifier, string? notice)
    {
        var url = GetBasePath(context) + "/" + section;

        if (!string.IsNullOrEmpty(identifier))
        {
            url += "/" + Uri.EscapeDataString(identifier);
        }

        return notice is null ? url : QueryHelpers.AddQueryString(url, QueryStringParameters.Notice, notice);
    }

    private IResult Page<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.All)] TComponent>(
        HttpContext context, Parameters parameters, int status = StatusCodes.Status200OK)
        where TComponent : IComponent
    {
        parameters["BasePath"] = GetBasePath(context);

        return new RazorComponentResult<TComponent>(parameters)
        {
            PreventStreamingRendering = true,
            StatusCode = status
        };
    }

    private IResult Message(HttpContext context, int status, string message) => Page<MessagePage>(context, new()
    {
        [nameof(MessagePage.StatusCode)] = status,
        [nameof(MessagePage.Message)] = message
    }, status);

    private IResult NotFound(HttpContext context)
        => Message(context, StatusCodes.Status404NotFound, SR.GetResourceString(SR.ID2342));

    private IResult ApplicationEditor(HttpContext context, int status, string? identifier,
        OpenIddictApplicationDescriptor descriptor, bool hasClientSecret, IReadOnlyList<string> errors,
        string? notice = null, string? secret = null)
    {
        // Note: the stored client secret must never be rendered.
        descriptor.ClientSecret = null;

        return Page<ApplicationEditorPage>(context, new()
        {
            [nameof(ApplicationEditorPage.Id)] = identifier,
            [nameof(ApplicationEditorPage.Descriptor)] = descriptor,
            [nameof(ApplicationEditorPage.HasClientSecret)] = hasClientSecret,
            [nameof(ApplicationEditorPage.NewClientSecret)] = secret,
            [nameof(ApplicationEditorPage.PublicJsonWebKeySet)] = FormatPublicJsonWebKeySet(descriptor.JsonWebKeySet),
            [nameof(ApplicationEditorPage.Errors)] = errors,
            [nameof(ApplicationEditorPage.Notice)] = notice
        }, status);
    }

    private IResult ScopeEditor(HttpContext context, int status, string? identifier,
        OpenIddictScopeDescriptor descriptor, IReadOnlyList<string> errors, string? notice = null)
        => Page<ScopeEditorPage>(context, new()
        {
            [nameof(ScopeEditorPage.Id)] = identifier,
            [nameof(ScopeEditorPage.Descriptor)] = descriptor,
            [nameof(ScopeEditorPage.Errors)] = errors,
            [nameof(ScopeEditorPage.Notice)] = notice
        }, status);

    private async Task<IResult> AuthorizationDetailsAsync(HttpContext context, int status,
        IOpenIddictAuthorizationManager manager, object authorization, IReadOnlyList<string> errors, string? notice = null)
    {
        var applications = GetManager<IOpenIddictApplicationManager>(context);
        var size = GetPagination(context).Size;

        var (identifier, descriptor) = await Operations.DescribeAuthorizationAsync(manager, authorization, context.RequestAborted);

        List<(string Id, OpenIddictTokenDescriptor Descriptor)> tokens = [];
        var more = false;

        // Note: at most one page of tokens is displayed. If more tokens are attached to the
        // authorization, the page indicates it and links to the filtered token list.
        if (!string.IsNullOrEmpty(identifier) && context.RequestServices.GetService<IOpenIddictTokenManager>() is { } manager2)
        {
            await foreach (var token in manager2.FindByAuthorizationIdAsync(identifier, context.RequestAborted))
            {
                if (tokens.Count == size)
                {
                    more = true;
                    break;
                }

                tokens.Add(await DescribeTokenAsync(manager2, token, context.RequestAborted));
            }
        }

        return Page<AuthorizationDetailsPage>(context, new()
        {
            [nameof(AuthorizationDetailsPage.Id)] = identifier ?? string.Empty,
            [nameof(AuthorizationDetailsPage.Descriptor)] = descriptor,
            [nameof(AuthorizationDetailsPage.Tokens)] = tokens,
            [nameof(AuthorizationDetailsPage.HasMoreTokens)] = more,
            [nameof(AuthorizationDetailsPage.ClientIds)] = await ResolveClientIdsAsync(applications,
                [descriptor.ApplicationId, .. tokens.Select(static token => token.Descriptor.ApplicationId)], context.RequestAborted),
            [nameof(AuthorizationDetailsPage.Errors)] = errors,
            [nameof(AuthorizationDetailsPage.Notice)] = notice
        }, status);
    }

    private async Task<IResult> TokenDetailsAsync(HttpContext context, int status,
        IOpenIddictTokenManager manager, object token, IReadOnlyList<string> errors, string? notice = null)
    {
        var applications = GetManager<IOpenIddictApplicationManager>(context);
        var (identifier, descriptor) = await DescribeTokenAsync(manager, token, context.RequestAborted);

        return Page<TokenDetailsPage>(context, new()
        {
            [nameof(TokenDetailsPage.Id)] = identifier,
            [nameof(TokenDetailsPage.Descriptor)] = descriptor,
            [nameof(TokenDetailsPage.ClientIds)] = await ResolveClientIdsAsync(applications,
                [descriptor.ApplicationId], context.RequestAborted),
            [nameof(TokenDetailsPage.Errors)] = errors,
            [nameof(TokenDetailsPage.Notice)] = notice
        }, status);
    }

    private async Task<IResult> SessionDetailsAsync(HttpContext context, int status, IOpenIddictSessionManager manager,
        object session, IReadOnlyList<string> errors, string? notice = null, OpenIddictServerSessionTerminationResult? result = null)
    {
        var applications = GetManager<IOpenIddictApplicationManager>(context);
        var size = GetPagination(context).Size;

        var (identifier, descriptor) = await DescribeSessionAsync(manager, session, context.RequestAborted);

        List<(string Id, OpenIddictTokenDescriptor Descriptor)> tokens = [];
        var more = false;

        // Note: at most one page of tokens is displayed.
        if (!string.IsNullOrEmpty(identifier) && context.RequestServices.GetService<IOpenIddictTokenManager>() is { } manager2)
        {
            await foreach (var token in manager2.FindBySessionIdAsync(identifier, context.RequestAborted))
            {
                if (tokens.Count == size)
                {
                    more = true;
                    break;
                }

                tokens.Add(await DescribeTokenAsync(manager2, token, context.RequestAborted));
            }
        }

        return Page<SessionDetailsPage>(context, new()
        {
            [nameof(SessionDetailsPage.Id)] = identifier,
            [nameof(SessionDetailsPage.Descriptor)] = descriptor,
            [nameof(SessionDetailsPage.Tokens)] = tokens,
            [nameof(SessionDetailsPage.HasMoreTokens)] = more,
            [nameof(SessionDetailsPage.ClientIds)] = await ResolveClientIdsAsync(applications,
                [descriptor.ApplicationId], context.RequestAborted),
            [nameof(SessionDetailsPage.Result)] = result,
            [nameof(SessionDetailsPage.Errors)] = errors,
            [nameof(SessionDetailsPage.Notice)] = notice
        }, status);
    }

    private async Task<IResult> KeyListAsync(HttpContext context, int status,
        IOpenIddictKeyManager manager, IReadOnlyList<string> errors, string? notice = null)
    {
        var (page, size, offset) = GetPagination(context);

        List<(string Id, OpenIddictKeyDescriptor Descriptor)> items = [];
        var next = false;

        await foreach (var key in manager.ListAsync(size + 1, offset, context.RequestAborted))
        {
            if (items.Count == size)
            {
                next = true;
                break;
            }

            var (identifier, descriptor) = await Operations.DescribeKeyAsync(manager, key, context.RequestAborted);

            // Note: the (protected) key material is deliberately never rendered.
            descriptor.Payload = null;

            items.Add((identifier ?? string.Empty, descriptor));
        }

        return Page<KeyListPage>(context, new()
        {
            [nameof(KeyListPage.Items)] = items,
            [nameof(KeyListPage.PageNumber)] = page,
            [nameof(KeyListPage.HasNextPage)] = next,
            [nameof(KeyListPage.Errors)] = errors,
            [nameof(KeyListPage.Notice)] = notice
        }, status);
    }

    private static async ValueTask<(string Id, OpenIddictTokenDescriptor Descriptor)> DescribeTokenAsync(
        IOpenIddictTokenManager manager, object token, CancellationToken cancellationToken)
    {
        var (identifier, descriptor) = await Operations.DescribeTokenAsync(manager, token, cancellationToken);

        // Note: the token payload is deliberately never rendered.
        descriptor.Payload = null;

        return (identifier ?? string.Empty, descriptor);
    }

    private static async ValueTask<(string Id, OpenIddictSessionDescriptor Descriptor)> DescribeSessionAsync(
        IOpenIddictSessionManager manager, object session, CancellationToken cancellationToken)
    {
        var (identifier, descriptor) = await Operations.DescribeSessionAsync(manager, session, cancellationToken);

        // Note: the principal attached to the session (that contains the claims of the end user) is deliberately never rendered.
        descriptor.Principal = null;

        return (identifier ?? string.Empty, descriptor);
    }

    private static async ValueTask<object?> FindByIdAsync(Func<string, CancellationToken, ValueTask<object?>> finder,
        string identifier, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(identifier))
        {
            return null;
        }

        try
        {
            return await finder(identifier, cancellationToken);
        }

        // Note: the identifiers are user-provided values (route segments or filters) that stores using non-string keys
        // (e.g Entity Framework Core with Guid or integer keys, MongoDB ObjectId) can't always convert: in this case,
        // the conversion error is treated as a missing entity instead of failing the whole request.
        catch (Exception exception) when (exception is FormatException or OverflowException ||
            (exception is ArgumentException && exception is not ArgumentNullException))
        {
            return null;
        }
    }

    private static async ValueTask<(bool Found, string? Identifier)> ResolveApplicationIdAsync(
        IOpenIddictApplicationManager manager, string? client, CancellationToken cancellationToken)
    {
        if (client is null)
        {
            return (true, null);
        }

        // Note: the client filter can be either a client identifier or an application identifier.
        var application = await manager.FindByClientIdAsync(client, cancellationToken) ??
                          await FindByIdAsync(manager.FindByIdAsync, client, cancellationToken);
        if (application is null)
        {
            return (false, null);
        }

        return (true, await manager.GetIdAsync(application, cancellationToken));
    }

    private static async ValueTask<IReadOnlyDictionary<string, string>> ResolveClientIdsAsync(
        IOpenIddictApplicationManager manager, IEnumerable<string?> identifiers, CancellationToken cancellationToken)
    {
        Dictionary<string, string> result = new(StringComparer.Ordinal);

        foreach (var identifier in identifiers)
        {
            if (string.IsNullOrEmpty(identifier) || result.ContainsKey(identifier))
            {
                continue;
            }

            if (await manager.FindByIdAsync(identifier, cancellationToken) is object application &&
                await manager.GetClientIdAsync(application, cancellationToken) is { Length: > 0 } client)
            {
                result[identifier] = client;
            }
        }

        return result;
    }

    private static string? FormatPublicJsonWebKeySet(JsonWebKeySet? set)
    {
        if (set is null)
        {
            return null;
        }

        var buffer = new ArrayBufferWriter<byte>();

        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            Operations.WritePublicJsonWebKeySet(writer, set);
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static string GenerateClientSecret() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    private static List<string> GetErrors(OpenIddictExceptions.ValidationException exception)
        => [SR.GetResourceString(SR.ID2245), .. exception.Results
            .Select(static result => result.ErrorMessage)
            .OfType<string>()];

    private sealed class Parameters() : Dictionary<string, object?>(StringComparer.Ordinal);

    private static void Log(HttpContext context, int id, string resource, params object?[] arguments)
    {
        var logger = context.RequestServices.GetRequiredService<ILoggerFactory>()
            .CreateLogger(typeof(OpenIddictServerAspNetCoreAdminUIEndpoints).FullName!);

        logger.LogInformation(id, SR.GetResourceString(resource), [.. arguments, context.User.Identity?.Name]);
    }
}
