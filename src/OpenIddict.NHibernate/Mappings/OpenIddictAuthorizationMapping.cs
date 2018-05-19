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
    /// Defines a relational mapping for the Authorization entity.
    /// </summary>
    /// <typeparam name="TAuthorization">The type of the Authorization entity.</typeparam>
    /// <typeparam name="TApplication">The type of the Application entity.</typeparam>
    /// <typeparam name="TToken">The type of the Token entity.</typeparam>
    /// <typeparam name="TKey">The type of the Key entity.</typeparam>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIddictAuthorizationMapping<TAuthorization, TApplication, TToken, TKey> : ClassMapping<TAuthorization>
        where TAuthorization : OpenIddictAuthorization<TKey, TApplication, TToken>
        where TApplication : OpenIddictApplication<TKey, TAuthorization, TToken>
        where TToken : OpenIddictToken<TKey, TApplication, TAuthorization>
        where TKey : IEquatable<TKey>
    {
        public OpenIddictAuthorizationMapping()
        {
            Id(authorization => authorization.Id, map =>
            {
                map.Generator(Generators.Identity);
            });

            Version(authorization => authorization.Version, map =>
            {
                map.Insert(true);
            });

            Property(authorization => authorization.Properties, map =>
            {
                map.Length(10000);
            });

            Property(authorization => authorization.Scopes, map =>
            {
                map.Length(10000);
            });

            Property(authorization => authorization.Status, map =>
            {
                map.NotNullable(true);
            });

            Property(authorization => authorization.Subject, map =>
            {
                map.NotNullable(true);
            });

            Property(authorization => authorization.Type, map =>
            {
                map.NotNullable(true);
            });

            ManyToOne(authorization => authorization.Application, map =>
            {
                map.ForeignKey("ApplicationId");
            });

            Bag(authorization => authorization.Tokens,
                map =>
                {
                    map.Key(key => key.Column("AuthorizationId"));
                },
                map =>
                {
                    map.OneToMany();
                });

            Table("OpenIddictAuthorizations");
        }
    }
}
