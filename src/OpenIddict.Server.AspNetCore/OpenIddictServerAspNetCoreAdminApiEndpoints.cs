/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Buffers;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using static OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.AdminApi;

namespace OpenIddict.Server.AspNetCore;

/// <summary>
/// Contains the request delegates of the OpenIddict admin API endpoints.
/// </summary>
internal static class OpenIddictServerAspNetCoreAdminApiEndpoints
{
    private const int DefaultCount = 100;
    private const int MaximumCount = 1000;

    // Private (RSA, EC, OKP, AKP) and symmetric (oct) key parameters.
    // See https://datatracker.ietf.org/doc/html/rfc7518#section-6 for more information.
    private static readonly HashSet<string> PrivateJsonWebKeyParameters = new(StringComparer.Ordinal)
    {
        "d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi"
    };

    public static Task ListApplicationsAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);
        var (count, offset) = GetPagination(context);

        List<(string? Identifier, OpenIddictApplicationDescriptor Descriptor)> entries = [];

        await foreach (var application in manager.ListAsync(count, offset, context.RequestAborted))
        {
            entries.Add(await DescribeApplicationAsync(manager, application, context.RequestAborted));
        }

        await WriteAsync(context, StatusCodes.Status200OK, writer =>
        {
            writer.WriteStartArray();

            foreach (var (identifier, descriptor) in entries)
            {
                WriteApplication(writer, identifier, descriptor);
            }

            writer.WriteEndArray();
        });
    });

    public static Task GetApplicationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object application)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var (identifier, descriptor) = await DescribeApplicationAsync(manager, application, context.RequestAborted);
        await WriteAsync(context, StatusCodes.Status200OK, writer => WriteApplication(writer, identifier, descriptor));
    });

    public static Task CreateApplicationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);

        using var document = await ReadBodyAsync(context);

        var descriptor = new OpenIddictApplicationDescriptor();
        ReadApplication(document.RootElement, descriptor);

        var application = await manager.CreateAsync(descriptor, context.RequestAborted);

        var (identifier, result) = await DescribeApplicationAsync(manager, application, context.RequestAborted);
        SetLocation(context, identifier);
        await WriteAsync(context, StatusCodes.Status201Created, writer => WriteApplication(writer, identifier, result));
    });

    public static Task UpdateApplicationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);

        using var document = await ReadBodyAsync(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object application)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var descriptor = new OpenIddictApplicationDescriptor();
        await manager.PopulateAsync(descriptor, application, context.RequestAborted);

        ReadApplication(document.RootElement, descriptor);

        await manager.UpdateAsync(application, descriptor, context.RequestAborted);

        var (identifier, result) = await DescribeApplicationAsync(manager, application, context.RequestAborted);
        await WriteAsync(context, StatusCodes.Status200OK, writer => WriteApplication(writer, identifier, result));
    });

    public static Task DeleteApplicationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictApplicationManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object application)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        await manager.DeleteAsync(application, context.RequestAborted);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    });

    public static Task ListScopesAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);
        var (count, offset) = GetPagination(context);

        List<(string? Identifier, OpenIddictScopeDescriptor Descriptor)> entries = [];

        await foreach (var scope in manager.ListAsync(count, offset, context.RequestAborted))
        {
            entries.Add(await DescribeScopeAsync(manager, scope, context.RequestAborted));
        }

        await WriteAsync(context, StatusCodes.Status200OK, writer =>
        {
            writer.WriteStartArray();

            foreach (var (identifier, descriptor) in entries)
            {
                WriteScope(writer, identifier, descriptor);
            }

            writer.WriteEndArray();
        });
    });

    public static Task GetScopeAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object scope)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var (identifier, descriptor) = await DescribeScopeAsync(manager, scope, context.RequestAborted);
        await WriteAsync(context, StatusCodes.Status200OK, writer => WriteScope(writer, identifier, descriptor));
    });

    public static Task CreateScopeAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);

        using var document = await ReadBodyAsync(context);

        var descriptor = new OpenIddictScopeDescriptor();
        ReadScope(document.RootElement, descriptor);

        var scope = await manager.CreateAsync(descriptor, context.RequestAborted);

        var (identifier, result) = await DescribeScopeAsync(manager, scope, context.RequestAborted);
        SetLocation(context, identifier);
        await WriteAsync(context, StatusCodes.Status201Created, writer => WriteScope(writer, identifier, result));
    });

    public static Task UpdateScopeAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);

        using var document = await ReadBodyAsync(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object scope)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var descriptor = new OpenIddictScopeDescriptor();
        await manager.PopulateAsync(descriptor, scope, context.RequestAborted);

        ReadScope(document.RootElement, descriptor);

        await manager.UpdateAsync(scope, descriptor, context.RequestAborted);

        var (identifier, result) = await DescribeScopeAsync(manager, scope, context.RequestAborted);
        await WriteAsync(context, StatusCodes.Status200OK, writer => WriteScope(writer, identifier, result));
    });

    public static Task DeleteScopeAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictScopeManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object scope)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        await manager.DeleteAsync(scope, context.RequestAborted);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    });

    public static Task ListAuthorizationsAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);
        var (count, offset) = GetPagination(context);
        var (subject, application, status, type) = GetFilters(context);

        var authorizations = subject is null && application is null && status is null && type is null ?
            manager.ListAsync(count, offset, context.RequestAborted) :
            PaginateAsync(manager.FindAsync((subject, application, status, type, null), context.RequestAborted),
                count, offset, context.RequestAborted);

        List<(string? Identifier, OpenIddictAuthorizationDescriptor Descriptor)> entries = [];

        await foreach (var authorization in authorizations.WithCancellation(context.RequestAborted))
        {
            entries.Add(await DescribeAuthorizationAsync(manager, authorization, context.RequestAborted));
        }

        await WriteAsync(context, StatusCodes.Status200OK, writer =>
        {
            writer.WriteStartArray();

            foreach (var (identifier, descriptor) in entries)
            {
                WriteAuthorization(writer, identifier, descriptor);
            }

            writer.WriteEndArray();
        });
    });

    public static Task GetAuthorizationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object authorization)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var (identifier, descriptor) = await DescribeAuthorizationAsync(manager, authorization, context.RequestAborted);
        await WriteAsync(context, StatusCodes.Status200OK, writer => WriteAuthorization(writer, identifier, descriptor));
    });

    public static Task CreateAuthorizationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);

        using var document = await ReadBodyAsync(context);

        var descriptor = new OpenIddictAuthorizationDescriptor();
        ReadAuthorization(document.RootElement, descriptor);

        var authorization = await manager.CreateAsync(descriptor, context.RequestAborted);

        var (identifier, result) = await DescribeAuthorizationAsync(manager, authorization, context.RequestAborted);
        SetLocation(context, identifier);
        await WriteAsync(context, StatusCodes.Status201Created, writer => WriteAuthorization(writer, identifier, result));
    });

    public static Task DeleteAuthorizationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object authorization)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        await manager.DeleteAsync(authorization, context.RequestAborted);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    });

    public static Task RevokeAuthorizationAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictAuthorizationManager>(context);

        (await ReadBodyAsync(context)).Dispose();

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object authorization)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (!await manager.TryRevokeAsync(authorization, context.RequestAborted))
        {
            throw new AdminApiException(StatusCodes.Status409Conflict, SR.GetResourceString(SR.ID2244));
        }

        // Revoke the tokens attached to the authorization so that they are no longer considered valid
        // (independently of whether token validation checks the status of the authorization entry).
        if (context.RequestServices.GetService<IOpenIddictTokenManager>() is IOpenIddictTokenManager tokens &&
            await manager.GetIdAsync(authorization, context.RequestAborted) is { Length: > 0 } identifier)
        {
            await tokens.RevokeByAuthorizationIdAsync(identifier, context.RequestAborted);
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
    });

    public static Task ListTokensAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictTokenManager>(context);
        var (count, offset) = GetPagination(context);
        var (subject, application, status, type) = GetFilters(context);

        var tokens = subject is null && application is null && status is null && type is null ?
            manager.ListAsync(count, offset, context.RequestAborted) :
            PaginateAsync(manager.FindAsync((subject, application, status, type), context.RequestAborted),
                count, offset, context.RequestAborted);

        List<(string? Identifier, OpenIddictTokenDescriptor Descriptor)> entries = [];

        await foreach (var token in tokens.WithCancellation(context.RequestAborted))
        {
            entries.Add(await DescribeTokenAsync(manager, token, context.RequestAborted));
        }

        await WriteAsync(context, StatusCodes.Status200OK, writer =>
        {
            writer.WriteStartArray();

            foreach (var (identifier, descriptor) in entries)
            {
                WriteToken(writer, identifier, descriptor);
            }

            writer.WriteEndArray();
        });
    });

    public static Task GetTokenAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictTokenManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object token)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var (identifier, descriptor) = await DescribeTokenAsync(manager, token, context.RequestAborted);
        await WriteAsync(context, StatusCodes.Status200OK, writer => WriteToken(writer, identifier, descriptor));
    });

    public static Task DeleteTokenAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictTokenManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object token)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        await manager.DeleteAsync(token, context.RequestAborted);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    });

    public static Task RevokeTokenAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictTokenManager>(context);

        (await ReadBodyAsync(context)).Dispose();

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object token)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (!await manager.TryRevokeAsync(token, context.RequestAborted))
        {
            throw new AdminApiException(StatusCodes.Status409Conflict, SR.GetResourceString(SR.ID2244));
        }

        context.Response.StatusCode = StatusCodes.Status204NoContent;
    });

    public static Task ListKeysAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictKeyManager>(context);
        var (count, offset) = GetPagination(context);

        List<(string? Identifier, OpenIddictKeyDescriptor Descriptor)> entries = [];

        await foreach (var key in manager.ListAsync(count, offset, context.RequestAborted))
        {
            entries.Add(await DescribeKeyAsync(manager, key, context.RequestAborted));
        }

        await WriteAsync(context, StatusCodes.Status200OK, writer =>
        {
            writer.WriteStartArray();

            foreach (var (identifier, descriptor) in entries)
            {
                WriteKey(writer, identifier, descriptor);
            }

            writer.WriteEndArray();
        });
    });

    public static Task GetKeyAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictKeyManager>(context);

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object key)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        var (identifier, descriptor) = await DescribeKeyAsync(manager, key, context.RequestAborted);
        await WriteAsync(context, StatusCodes.Status200OK, writer => WriteKey(writer, identifier, descriptor));
    });

    public static Task RevokeKeyAsync(HttpContext context) => ExecuteAsync(context, static async context =>
    {
        var manager = GetManager<IOpenIddictKeyManager>(context);

        (await ReadBodyAsync(context)).Dispose();

        if (await manager.FindByIdAsync(GetIdentifier(context), context.RequestAborted) is not object key)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (!await manager.TryRevokeAsync(key, context.RequestAborted))
        {
            throw new AdminApiException(StatusCodes.Status409Conflict, SR.GetResourceString(SR.ID2244));
        }

        // Discard the credentials cached by the key ring so that the revoked key is no longer used.
        context.RequestServices.GetService<OpenIddictServerKeyRing>()?.Invalidate();

        context.Response.StatusCode = StatusCodes.Status204NoContent;
    });

    private static async Task ExecuteAsync(HttpContext context, Func<HttpContext, Task> handler)
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";

        try
        {
            await handler(context);
        }

        catch (AdminApiException exception)
        {
            await WriteErrorAsync(context, exception.StatusCode, exception.Message, errors: []);
        }

        catch (OpenIddictExceptions.ValidationException exception)
        {
            await WriteErrorAsync(context, StatusCodes.Status400BadRequest, SR.GetResourceString(SR.ID2245),
                [.. exception.Results.Select(static result => result.ErrorMessage ?? string.Empty)]);
        }

        catch (OpenIddictExceptions.ConcurrencyException)
        {
            await WriteErrorAsync(context, StatusCodes.Status409Conflict, SR.GetResourceString(SR.ID2244), errors: []);
        }
    }

    private static TManager GetManager<TManager>(HttpContext context) where TManager : notnull
        => context.RequestServices.GetService<TManager>() ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0564));

    private static string GetIdentifier(HttpContext context)
        => context.Request.RouteValues["id"] as string is { Length: > 0 } identifier ? identifier :
            throw new AdminApiException(StatusCodes.Status404NotFound, SR.FormatID2243("id"));

    private static (int Count, int Offset) GetPagination(HttpContext context)
    {
        return (Parse(QueryStringParameters.Count, DefaultCount, minimum: 1),
                Parse(QueryStringParameters.Offset, 0, minimum: 0));

        int Parse(string name, int value, int minimum)
        {
            var parameter = (string?) context.Request.Query[name];
            if (string.IsNullOrEmpty(parameter))
            {
                return value;
            }

            if (!int.TryParse(parameter, NumberStyles.None, CultureInfo.InvariantCulture, out var result) ||
                result < minimum || (name is QueryStringParameters.Count && result > MaximumCount))
            {
                throw new AdminApiException(StatusCodes.Status400BadRequest, SR.FormatID2243(name));
            }

            return result;
        }
    }

    private static (string? Subject, string? ApplicationId, string? Status, string? Type) GetFilters(HttpContext context)
    {
        return (Get(QueryStringParameters.Subject), Get(QueryStringParameters.ApplicationId),
                Get(QueryStringParameters.Status), Get(QueryStringParameters.Type));

        string? Get(string name) => (string?) context.Request.Query[name] is { Length: > 0 } value ? value : null;
    }

    private static async IAsyncEnumerable<object> PaginateAsync(IAsyncEnumerable<object> source,
        int count, int offset, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var index = 0;

        await foreach (var item in source.WithCancellation(cancellationToken))
        {
            if (index++ < offset)
            {
                continue;
            }

            yield return item;

            if (index - offset >= count)
            {
                yield break;
            }
        }
    }

    private static void SetLocation(HttpContext context, string? identifier)
    {
        if (!string.IsNullOrEmpty(identifier))
        {
            context.Response.Headers.Location = string.Concat(
                context.Request.PathBase.Add(context.Request.Path).Value?.TrimEnd('/'), "/", Uri.EscapeDataString(identifier));
        }
    }

    private static async Task<JsonDocument> ReadBodyAsync(HttpContext context)
    {
        if (!context.Request.HasJsonContentType())
        {
            throw new AdminApiException(StatusCodes.Status415UnsupportedMediaType, SR.GetResourceString(SR.ID2241));
        }

        using var buffer = new MemoryStream();
        await context.Request.Body.CopyToAsync(buffer, context.RequestAborted);

        if (buffer.Length is 0)
        {
            return JsonDocument.Parse("{}");
        }

        JsonDocument document;

        try
        {
            document = JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int) buffer.Length));
        }

        catch (JsonException)
        {
            throw new AdminApiException(StatusCodes.Status400BadRequest, SR.GetResourceString(SR.ID2241));
        }

        if (document.RootElement.ValueKind is not JsonValueKind.Object)
        {
            document.Dispose();
            throw new AdminApiException(StatusCodes.Status400BadRequest, SR.GetResourceString(SR.ID2241));
        }

        return document;
    }

    private static async Task WriteAsync(HttpContext context, int status, Action<Utf8JsonWriter> action)
    {
        // Note: the response is fully generated in memory before being written to the response
        // stream to ensure no partial payload is returned if an exception is thrown while writing.
        var buffer = new ArrayBufferWriter<byte>();

        using (var writer = new Utf8JsonWriter(buffer))
        {
            action(writer);
        }

        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json;charset=UTF-8";

        await context.Response.Body.WriteAsync(buffer.WrittenMemory, context.RequestAborted);
    }

    private static Task WriteErrorAsync(HttpContext context, int status, string description, string[] errors)
        => WriteAsync(context, status, writer =>
        {
            writer.WriteStartObject();
            writer.WriteString(Parameters.Error, status switch
            {
                StatusCodes.Status404NotFound => ErrorCodes.NotFound,
                StatusCodes.Status409Conflict => ErrorCodes.Conflict,
                _ => Errors.InvalidRequest
            });
            writer.WriteString(Parameters.ErrorDescription, description);

            if (errors is [_, ..])
            {
                writer.WriteStartArray(Fields.Errors);

                foreach (var error in errors)
                {
                    writer.WriteStringValue(error);
                }

                writer.WriteEndArray();
            }

            writer.WriteEndObject();
        });

    private static async ValueTask<(string?, OpenIddictApplicationDescriptor)> DescribeApplicationAsync(
        IOpenIddictApplicationManager manager, object application, CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictApplicationDescriptor();
        await manager.PopulateAsync(descriptor, application, cancellationToken);

        return (await manager.GetIdAsync(application, cancellationToken), descriptor);
    }

    private static async ValueTask<(string?, OpenIddictScopeDescriptor)> DescribeScopeAsync(
        IOpenIddictScopeManager manager, object scope, CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictScopeDescriptor();
        await manager.PopulateAsync(descriptor, scope, cancellationToken);

        return (await manager.GetIdAsync(scope, cancellationToken), descriptor);
    }

    private static async ValueTask<(string?, OpenIddictAuthorizationDescriptor)> DescribeAuthorizationAsync(
        IOpenIddictAuthorizationManager manager, object authorization, CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictAuthorizationDescriptor();
        await manager.PopulateAsync(descriptor, authorization, cancellationToken);

        return (await manager.GetIdAsync(authorization, cancellationToken), descriptor);
    }

    private static async ValueTask<(string?, OpenIddictTokenDescriptor)> DescribeTokenAsync(
        IOpenIddictTokenManager manager, object token, CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictTokenDescriptor();
        await manager.PopulateAsync(descriptor, token, cancellationToken);

        return (await manager.GetIdAsync(token, cancellationToken), descriptor);
    }

    private static async ValueTask<(string?, OpenIddictKeyDescriptor)> DescribeKeyAsync(
        IOpenIddictKeyManager manager, object key, CancellationToken cancellationToken)
    {
        var descriptor = new OpenIddictKeyDescriptor();
        await manager.PopulateAsync(descriptor, key, cancellationToken);

        return (await manager.GetIdAsync(key, cancellationToken), descriptor);
    }

    private static void WriteApplication(Utf8JsonWriter writer, string? identifier, OpenIddictApplicationDescriptor descriptor)
    {
        // Note: the client secret is deliberately never returned.
        writer.WriteStartObject();
        writer.WriteString(Fields.Id, identifier);
        writer.WriteString(Fields.ApplicationType, descriptor.ApplicationType);
        writer.WriteString(Fields.ClientId, descriptor.ClientId);
        writer.WriteString(Fields.ClientType, descriptor.ClientType);
        writer.WriteString(Fields.ConsentType, descriptor.ConsentType);
        writer.WriteString(Fields.DisplayName, descriptor.DisplayName);
        WriteCultures(writer, Fields.DisplayNames, descriptor.DisplayNames);

        writer.WritePropertyName(Fields.JsonWebKeySet);

        if (descriptor.JsonWebKeySet is not null)
        {
            using var set = JsonDocument.Parse(JsonSerializer.SerializeToUtf8Bytes(
                descriptor.JsonWebKeySet, OpenIddictSerializer.Default.JsonWebKeySet));

            WritePublicJsonWebKeySet(writer, set.RootElement);
        }

        else
        {
            writer.WriteNullValue();
        }

        WriteStrings(writer, Fields.Permissions, descriptor.Permissions);
        WriteStrings(writer, Fields.PostLogoutRedirectUris, descriptor.PostLogoutRedirectUris.Select(static uri => uri.AbsoluteUri));
        WriteStrings(writer, Fields.RedirectUris, descriptor.RedirectUris.Select(static uri => uri.AbsoluteUri));
        WriteStrings(writer, Fields.Requirements, descriptor.Requirements);

        writer.WriteStartObject(Fields.Settings);

        foreach (var setting in descriptor.Settings.OrderBy(static setting => setting.Key, StringComparer.Ordinal))
        {
            writer.WriteString(setting.Key, setting.Value);
        }

        writer.WriteEndObject();

        WriteProperties(writer, descriptor.Properties);
        writer.WriteEndObject();
    }

    private static void WritePublicJsonWebKeySet(Utf8JsonWriter writer, JsonElement set)
    {
        // Note: the private and symmetric key parameters (that may have been attached to the client
        // JSON Web Key Set, even if only public keys are expected) are deliberately never returned.
        writer.WriteStartObject();

        foreach (var property in set.EnumerateObject())
        {
            if (!property.NameEquals(JsonWebKeySetParameterNames.Keys) || property.Value.ValueKind is not JsonValueKind.Array)
            {
                property.WriteTo(writer);
                continue;
            }

            writer.WriteStartArray(property.Name);

            foreach (var key in property.Value.EnumerateArray())
            {
                if (key.ValueKind is not JsonValueKind.Object)
                {
                    continue;
                }

                writer.WriteStartObject();

                foreach (var parameter in key.EnumerateObject())
                {
                    if (!PrivateJsonWebKeyParameters.Contains(parameter.Name))
                    {
                        parameter.WriteTo(writer);
                    }
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        writer.WriteEndObject();
    }

    private static void WriteScope(Utf8JsonWriter writer, string? identifier, OpenIddictScopeDescriptor descriptor)
    {
        writer.WriteStartObject();
        writer.WriteString(Fields.Id, identifier);
        writer.WriteString(Fields.Name, descriptor.Name);
        writer.WriteString(Fields.DisplayName, descriptor.DisplayName);
        WriteCultures(writer, Fields.DisplayNames, descriptor.DisplayNames);
        writer.WriteString(Fields.Description, descriptor.Description);
        WriteCultures(writer, Fields.Descriptions, descriptor.Descriptions);
        WriteStrings(writer, Fields.Resources, descriptor.Resources);
        WriteProperties(writer, descriptor.Properties);
        writer.WriteEndObject();
    }

    private static void WriteAuthorization(Utf8JsonWriter writer, string? identifier, OpenIddictAuthorizationDescriptor descriptor)
    {
        writer.WriteStartObject();
        writer.WriteString(Fields.Id, identifier);
        writer.WriteString(Fields.ApplicationId, descriptor.ApplicationId);
        WriteDate(writer, Fields.CreationDate, descriptor.CreationDate);
        WriteStrings(writer, Fields.Scopes, descriptor.Scopes);
        writer.WriteString(Fields.Status, descriptor.Status);
        writer.WriteString(Fields.Subject, descriptor.Subject);
        writer.WriteString(Fields.Type, descriptor.Type);
        WriteProperties(writer, descriptor.Properties);
        writer.WriteEndObject();
    }

    private static void WriteToken(Utf8JsonWriter writer, string? identifier, OpenIddictTokenDescriptor descriptor)
    {
        // Note: the payload and the reference identifier are deliberately never returned.
        writer.WriteStartObject();
        writer.WriteString(Fields.Id, identifier);
        writer.WriteString(Fields.ApplicationId, descriptor.ApplicationId);
        writer.WriteString(Fields.AuthorizationId, descriptor.AuthorizationId);
        WriteDate(writer, Fields.CreationDate, descriptor.CreationDate);
        WriteDate(writer, Fields.ExpirationDate, descriptor.ExpirationDate);
        WriteDate(writer, Fields.RedemptionDate, descriptor.RedemptionDate);
        writer.WriteString(Fields.SessionId, descriptor.SessionId);
        writer.WriteString(Fields.Status, descriptor.Status);
        writer.WriteString(Fields.Subject, descriptor.Subject);
        writer.WriteString(Fields.Type, descriptor.Type);
        WriteProperties(writer, descriptor.Properties);
        writer.WriteEndObject();
    }

    private static void WriteKey(Utf8JsonWriter writer, string? identifier, OpenIddictKeyDescriptor descriptor)
    {
        // Note: the (protected) key material is deliberately never returned.
        writer.WriteStartObject();
        writer.WriteString(Fields.Id, identifier);
        writer.WriteString(Fields.KeyId, descriptor.KeyId);
        writer.WriteString(Fields.Algorithm, descriptor.Algorithm);
        writer.WriteString(Fields.Usage, descriptor.Usage);
        writer.WriteString(Fields.Status, descriptor.Status);
        WriteDate(writer, Fields.CreationDate, descriptor.CreationDate);
        WriteDate(writer, Fields.ActivationDate, descriptor.ActivationDate);
        WriteDate(writer, Fields.ExpirationDate, descriptor.ExpirationDate);
        WriteDate(writer, Fields.RetirementDate, descriptor.RetirementDate);
        WriteProperties(writer, descriptor.Properties);
        writer.WriteEndObject();
    }

    private static void WriteCultures(Utf8JsonWriter writer, string name, Dictionary<CultureInfo, string> values)
    {
        writer.WriteStartObject(name);

        foreach (var value in values.OrderBy(static value => value.Key.Name, StringComparer.Ordinal))
        {
            writer.WriteString(value.Key.Name, value.Value);
        }

        writer.WriteEndObject();
    }

    private static void WriteDate(Utf8JsonWriter writer, string name, DateTimeOffset? date)
    {
        if (date is DateTimeOffset value)
        {
            writer.WriteString(name, value);
        }

        else
        {
            writer.WriteNull(name);
        }
    }

    private static void WriteProperties(Utf8JsonWriter writer, Dictionary<string, JsonElement> properties)
    {
        writer.WriteStartObject(Fields.Properties);

        foreach (var property in properties.OrderBy(static property => property.Key, StringComparer.Ordinal))
        {
            writer.WritePropertyName(property.Key);
            property.Value.WriteTo(writer);
        }

        writer.WriteEndObject();
    }

    private static void WriteStrings(Utf8JsonWriter writer, string name, IEnumerable<string> values)
    {
        writer.WriteStartArray(name);

        foreach (var value in values.Order(StringComparer.Ordinal))
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }

    private static void ReadApplication(JsonElement element, OpenIddictApplicationDescriptor descriptor)
    {
        foreach (var property in element.EnumerateObject())
        {
            switch (property.Name)
            {
                case Fields.Id: break;

                case Fields.ApplicationType: descriptor.ApplicationType = ReadString(property); break;
                case Fields.ClientId:        descriptor.ClientId        = ReadString(property); break;
                case Fields.ClientSecret:    descriptor.ClientSecret    = ReadString(property); break;
                case Fields.ClientType:      descriptor.ClientType      = ReadString(property); break;
                case Fields.ConsentType:     descriptor.ConsentType     = ReadString(property); break;
                case Fields.DisplayName:     descriptor.DisplayName     = ReadString(property); break;

                case Fields.DisplayNames:
                    ReadCultures(property, descriptor.DisplayNames);
                    break;

                case Fields.JsonWebKeySet:
                    descriptor.JsonWebKeySet = ReadJsonWebKeySet(property);
                    break;

                case Fields.Permissions:
                    ReadStrings(property, descriptor.Permissions);
                    break;

                case Fields.PostLogoutRedirectUris:
                    ReadUris(property, descriptor.PostLogoutRedirectUris);
                    break;

                case Fields.RedirectUris:
                    ReadUris(property, descriptor.RedirectUris);
                    break;

                case Fields.Requirements:
                    ReadStrings(property, descriptor.Requirements);
                    break;

                case Fields.Settings:
                    ReadSettings(property, descriptor.Settings);
                    break;

                case Fields.Properties:
                    ReadProperties(property, descriptor.Properties);
                    break;

                default: throw InvalidProperty(property.Name);
            }
        }
    }

    private static void ReadScope(JsonElement element, OpenIddictScopeDescriptor descriptor)
    {
        foreach (var property in element.EnumerateObject())
        {
            switch (property.Name)
            {
                case Fields.Id: break;

                case Fields.Name:        descriptor.Name        = ReadString(property); break;
                case Fields.DisplayName: descriptor.DisplayName = ReadString(property); break;
                case Fields.Description: descriptor.Description = ReadString(property); break;

                case Fields.DisplayNames:
                    ReadCultures(property, descriptor.DisplayNames);
                    break;

                case Fields.Descriptions:
                    ReadCultures(property, descriptor.Descriptions);
                    break;

                case Fields.Resources:
                    ReadStrings(property, descriptor.Resources);
                    break;

                case Fields.Properties:
                    ReadProperties(property, descriptor.Properties);
                    break;

                default: throw InvalidProperty(property.Name);
            }
        }
    }

    private static void ReadAuthorization(JsonElement element, OpenIddictAuthorizationDescriptor descriptor)
    {
        foreach (var property in element.EnumerateObject())
        {
            switch (property.Name)
            {
                case Fields.Id: break;

                case Fields.ApplicationId: descriptor.ApplicationId = ReadString(property); break;
                case Fields.Status:        descriptor.Status        = ReadString(property); break;
                case Fields.Subject:       descriptor.Subject       = ReadString(property); break;
                case Fields.Type:          descriptor.Type          = ReadString(property); break;

                case Fields.CreationDate:
                    descriptor.CreationDate = property.Value.ValueKind switch
                    {
                        JsonValueKind.Null => null,
                        JsonValueKind.String when property.Value.TryGetDateTimeOffset(out var date) => date,
                        _ => throw InvalidProperty(property.Name)
                    };
                    break;

                case Fields.Scopes:
                    ReadStrings(property, descriptor.Scopes);
                    break;

                case Fields.Properties:
                    ReadProperties(property, descriptor.Properties);
                    break;

                default: throw InvalidProperty(property.Name);
            }
        }
    }

    private static string? ReadString(JsonProperty property) => property.Value.ValueKind switch
    {
        JsonValueKind.Null   => null,
        JsonValueKind.String => property.Value.GetString(),
        _ => throw InvalidProperty(property.Name)
    };

    private static void ReadStrings(JsonProperty property, HashSet<string> values)
    {
        values.Clear();

        if (property.Value.ValueKind is JsonValueKind.Null)
        {
            return;
        }

        if (property.Value.ValueKind is not JsonValueKind.Array)
        {
            throw InvalidProperty(property.Name);
        }

        foreach (var item in property.Value.EnumerateArray())
        {
            if (item.ValueKind is not JsonValueKind.String || string.IsNullOrEmpty(item.GetString()))
            {
                throw InvalidProperty(property.Name);
            }

            values.Add(item.GetString()!);
        }
    }

    private static void ReadUris(JsonProperty property, HashSet<Uri> values)
    {
        HashSet<string> strings = new(StringComparer.Ordinal);
        ReadStrings(property, strings);

        values.Clear();

        foreach (var value in strings)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
            {
                throw InvalidProperty(property.Name);
            }

            values.Add(uri);
        }
    }

    private static void ReadCultures(JsonProperty property, Dictionary<CultureInfo, string> values)
    {
        values.Clear();

        if (property.Value.ValueKind is JsonValueKind.Null)
        {
            return;
        }

        if (property.Value.ValueKind is not JsonValueKind.Object)
        {
            throw InvalidProperty(property.Name);
        }

        foreach (var item in property.Value.EnumerateObject())
        {
            if (item.Value.ValueKind is not JsonValueKind.String)
            {
                throw InvalidProperty(property.Name);
            }

            CultureInfo culture;

            try
            {
                culture = CultureInfo.GetCultureInfo(item.Name);
            }

            catch (CultureNotFoundException)
            {
                throw InvalidProperty(property.Name);
            }

            values[culture] = item.Value.GetString()!;
        }
    }

    private static void ReadSettings(JsonProperty property, Dictionary<string, string> values)
    {
        values.Clear();

        if (property.Value.ValueKind is JsonValueKind.Null)
        {
            return;
        }

        if (property.Value.ValueKind is not JsonValueKind.Object)
        {
            throw InvalidProperty(property.Name);
        }

        foreach (var item in property.Value.EnumerateObject())
        {
            if (item.Value.ValueKind is not JsonValueKind.String)
            {
                throw InvalidProperty(property.Name);
            }

            values[item.Name] = item.Value.GetString()!;
        }
    }

    private static void ReadProperties(JsonProperty property, Dictionary<string, JsonElement> values)
    {
        values.Clear();

        if (property.Value.ValueKind is JsonValueKind.Null)
        {
            return;
        }

        if (property.Value.ValueKind is not JsonValueKind.Object)
        {
            throw InvalidProperty(property.Name);
        }

        foreach (var item in property.Value.EnumerateObject())
        {
            // Note: the elements are cloned as the JSON document is disposed when the request is processed.
            values[item.Name] = item.Value.Clone();
        }
    }

    private static JsonWebKeySet? ReadJsonWebKeySet(JsonProperty property)
    {
        if (property.Value.ValueKind is JsonValueKind.Null)
        {
            return null;
        }

        if (property.Value.ValueKind is not JsonValueKind.Object)
        {
            throw InvalidProperty(property.Name);
        }

        try
        {
            return JsonWebKeySet.Create(property.Value.GetRawText());
        }

        catch (Exception exception) when (exception is ArgumentException or JsonException or FormatException)
        {
            throw InvalidProperty(property.Name);
        }
    }

    private static AdminApiException InvalidProperty(string name)
        => new(StatusCodes.Status400BadRequest, SR.FormatID2242(name));

    private sealed class AdminApiException(int statusCode, string message) : Exception(message)
    {
        public int StatusCode { get; } = statusCode;
    }
}
