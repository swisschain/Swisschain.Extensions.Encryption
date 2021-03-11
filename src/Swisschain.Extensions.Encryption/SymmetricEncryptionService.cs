using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Swisschain.Extensions.Encryption
{
    public class SymmetricEncryptionService : ISymmetricEncryptionService
    {
        private readonly byte[] _secret;

        private const int KeyBitSize = 256;
        private const int NonceBitSize = 128;

        private readonly SecureRandom _random;

        public SymmetricEncryptionService(string secret)
        {
            _secret = Convert.FromBase64String(secret);
            _random = new SecureRandom();
        }

        public string Encrypt(string data)
        {
            return Encrypt(data, _secret, null);
        }

        public string Encrypt(string data, byte[] key, byte[] nonce)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("data required!", nameof(data));

            var dataBytes = Encoding.UTF8.GetBytes(data);
            var encryptedData = EncryptWithKey(dataBytes, key, nonce);

            return Convert.ToBase64String(encryptedData);
        }

        public string Decrypt(string data)
        {
            return Decrypt(data, _secret, null);
        }

        public string Decrypt(string data, byte[] key, byte[] nonce)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("data is required!", nameof(data));

            var cipherData = Convert.FromBase64String(data);
            var plainText = DecryptWithKey(cipherData, key, nonce);

            return Encoding.UTF8.GetString(plainText);
        }

        public string GenerateKey()
        {
            var key = new byte[KeyBitSize / 8];
            _random.NextBytes(key);
            key[^1] &= 0x7F;
            return Convert.ToBase64String(key);
        }

        private byte[] DecryptWithKey(byte[] message, byte[] key, byte[] nonce = null)
        {
            if (key == null || key.Length != KeyBitSize / 8)
                throw new ArgumentException($"Key needs to be {KeyBitSize} bit!", nameof(key));

            if (message == null || message.Length == 0)
                throw new ArgumentException("Message required!", nameof(message));

            using (var cipherStream = new MemoryStream(message))
            using (var cipherReader = new BinaryReader(cipherStream))
            {
                var cipherNonce = nonce ?? cipherReader.ReadBytes(NonceBitSize / 8);
                var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
                var parameters = new ParametersWithIV(new KeyParameter(key), cipherNonce);
                cipher.Init(false, parameters);

                var cipherData = nonce != null
                    ? message
                    : cipherReader.ReadBytes(message.Length - cipherNonce.Length);

                var buffer = new byte[cipher.GetOutputSize(cipherData.Length)];
                var length = cipher.ProcessBytes(cipherData, buffer, 0);
                try
                {
                    cipher.DoFinal(buffer, length);
                }
                catch (InvalidCipherTextException)
                {
                    return null;
                }

                return Trim(buffer);
            }
        }

        private byte[] EncryptWithKey(byte[] data, byte[] key, byte[] nonce = null)
        {
            if (key == null || key.Length != KeyBitSize / 8)
                throw new ArgumentException($"Key needs to be {KeyBitSize} bit!", nameof(key));

            var cipherNonce = nonce ?? new byte[NonceBitSize / 8];

            if (cipherNonce.Length == 0)
            {
                _random.NextBytes(cipherNonce, 0, cipherNonce.Length);
            }

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
            var parameters = new ParametersWithIV(new KeyParameter(key), cipherNonce);
            cipher.Init(true, parameters);
            var buffer = new byte[cipher.GetOutputSize(data.Length)];
            var length = cipher.ProcessBytes(data, buffer, 0);
            try
            {
                cipher.DoFinal(buffer, length);
            }
            catch (InvalidCipherTextException)
            {
                return null;
            }

            using var combinedStream = new MemoryStream();
            using (var binaryWriter = new BinaryWriter(combinedStream))
            {
                binaryWriter.Write(cipherNonce);
                binaryWriter.Write(buffer);
            }

            return combinedStream.ToArray();
        }

        private byte[] Trim(byte[] data)
        {
            int length = 0;

            foreach (var item in data)
            {
                if (item == 0)
                    break;
                length++;
            }

            var result = new byte[length];
            Array.Copy(data, result, length);
            return result;
        }
    }
}
