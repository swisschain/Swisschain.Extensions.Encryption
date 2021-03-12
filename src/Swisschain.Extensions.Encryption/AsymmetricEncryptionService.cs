using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

namespace Swisschain.Extensions.Encryption
{
    public class AsymmetricEncryptionService
    {
        private const long PublicExponent = 3;
        private const int Strength = 1024;
        private const int Certainty = 25;
        private const string PrivateKeyType = "RSA PRIVATE KEY";
        private const string PublicKeyType = "PUBLIC KEY";
        private readonly SecureRandom _random;

        public AsymmetricEncryptionService()
        {
            _random = new SecureRandom();
        }

        public AsymmetricEncryptionKeyPair GenerateKeyPairPem()
        {
            var keyPairGenerator = new RsaKeyPairGenerator();

            var parameters = new RsaKeyGenerationParameters(BigInteger.ValueOf(PublicExponent),
                _random, Strength, Certainty);

            keyPairGenerator.Init(parameters);

            var keyPair = keyPairGenerator.GenerateKeyPair();

            var privateKey = ExportPrivateKey(keyPair.Private);
            var publicKey = ExportPublicKey(keyPair.Public);

            return new AsymmetricEncryptionKeyPair(privateKey, publicKey);
        }

        public byte[] GenerateSignature(byte[] data, string privateKey)
        {
            var signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(true, GetPrivateKeyParameters(privateKey));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] data, byte[] signature, string publicKey)
        {
            var signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(false, GetPublicKeyParameters(publicKey));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        public byte[] Encrypt(byte[] data, string publicKey)
        {
            var cipher = new Pkcs1Encoding(new RsaEngine());
            cipher.Init(true, GetPublicKeyParameters(publicKey));
            return cipher.ProcessBlock(data, 0, data.Length);
        }

        public byte[] Decrypt(byte[] data, string privateKey)
        {
            var cipher = new Pkcs1Encoding(new RsaEngine());
            cipher.Init(false, GetPrivateKeyParameters(privateKey));
            return cipher.ProcessBlock(data, 0, data.Length);
        }

        private AsymmetricKeyParameter GetPrivateKeyParameters(string privateKey)
        {
            using var reader = new StringReader(privateKey);
            var pemReader = new PemReader(reader);
            return PrivateKeyFactory.CreateKey(pemReader.ReadPemObject().Content);
        }

        private RsaKeyParameters GetPublicKeyParameters(string publicKey)
        {
            using var reader = new StringReader(publicKey);
            var pemReader = new PemReader(reader);
            var content = pemReader.ReadPemObject().Content;
            var asn1PublicKey = SubjectPublicKeyInfo.GetInstance(content).ParsePublicKey();
            var key = RsaPublicKeyStructure.GetInstance(asn1PublicKey);

            return new RsaKeyParameters(false, key.Modulus, key.PublicExponent);
        }

        private string ExportPrivateKey(AsymmetricKeyParameter privateKeyParameter)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParameter);
            using var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            pemWriter.WriteObject(new PemObject(PrivateKeyType, privateKeyInfo.GetEncoded()));
            pemWriter.Writer.Flush();
            return writer.ToString();
        }

        private string ExportPublicKey(AsymmetricKeyParameter keyParameter)
        {
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyParameter);
            var encodedKey = publicKeyInfo.ToAsn1Object().GetEncoded();
            using var writer = new StringWriter();
            var pemWriter = new PemWriter(writer);
            pemWriter.WriteObject(new PemObject(PublicKeyType, encodedKey));
            pemWriter.Writer.Flush();
            return writer.ToString();
        }
    }
}
