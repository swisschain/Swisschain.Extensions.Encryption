namespace Swisschain.Extensions.Encryption
{
    public interface ISymmetricEncryptionService
    {
        string Encrypt(string data);
        string Encrypt(string data, byte[] key, byte[] nonce);
        string Decrypt(string data);
        string Decrypt(string data, byte[] key, byte[] nonce);
        string GenerateKey();
    }
}
