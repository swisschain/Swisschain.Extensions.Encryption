namespace Swisschain.Extensions.Encryption
{
    public class AsymmetricEncryptionKeyPair
    {
        private readonly string _privateKey;
        private readonly string _publicKey;

        public AsymmetricEncryptionKeyPair(string privateKey, string publicKey)
        {
            _privateKey = privateKey;
            _publicKey = publicKey;
        }

        public string GetPrivateKey() => _privateKey;
        public string GetPublicKey() => _publicKey;
    }
}
