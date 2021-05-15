using MongoDB.Bson;

namespace OpenIddict.MongoDb.KeyGenerators
{
    public sealed class ObjectIdKeyGenerator : IKeyGenerator<ObjectId>
    {
        public static readonly IKeyGenerator<ObjectId> Default = new ObjectIdKeyGenerator();

        private ObjectIdKeyGenerator()
        {
        }

        /// <inheritdoc />
        public ObjectId Generate()
        {
            return ObjectId.GenerateNewId();
        }

        /// <inheritdoc />
        public ObjectId GenerateEmpty()
        {
            return ObjectId.Empty;
        }

        /// <inheritdoc />
        public ObjectId Parse(string input)
        {
            return ObjectId.Parse(input);
        }

        /// <inheritdoc />
        public bool IsUndefined(ObjectId input)
        {
            return input == ObjectId.Empty;
        }
    }
}
