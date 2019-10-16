/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;
using OpenIddict.NHibernate.Models;

namespace OpenIddict.NHibernate
{
    /// <summary>
    /// Defines a relational mapping for the Token entity.
    /// </summary>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictTokenMapping<TToken, TApplication, TAuthorization, TKey> : ClassMapping<TToken>
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictTokenMapping()
        {
            Id(token => token.Id, map =>
            {
                map.Generator(Generators.Identity);
            });

            Version(token => token.Version, map =>
            {
                map.Insert(true);
            });

            Property(token => token.CreationDate);

            Property(token => token.ExpirationDate);

            Property(token => token.Payload, map =>
            {
                map.Length(10000);
            });

            Property(token => token.Properties, map =>
            {
                map.Length(10000);
            });

            Property(token => token.ReferenceId);

            Property(token => token.Status, map =>
            {
                map.NotNullable(true);
            });

            Property(token => token.Type, map =>
            {
                map.NotNullable(true);
            });

            ManyToOne(token => token.Application, map =>
            {
                map.Column("ApplicationId");
            });

            ManyToOne(token => token.Authorization, map =>
            {
                map.Column("AuthorizationId");
            });

            Table("OpenIddictTokens");
        }
    }
}
