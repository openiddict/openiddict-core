namespace OpenIddict.MongoDb
{
    /// <summary>
    /// Implement this class to generate keys.
    /// </summary>
    /// <typeparam name="TKey">The type of the key.</typeparam>
    public interface IKeyGenerator<TKey> where TKey : notnull
    {
        TKey Generate();

        TKey GenerateEmpty();

        TKey Parse(string input);

        bool IsUndefined(TKey input);
    }
}
