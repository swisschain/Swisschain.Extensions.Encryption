using System;
using System.Text;
using Xunit;

namespace Swisschain.Extensions.Encryption.Tests
{
    public class AsymmetricEncryptionServiceTests
    {
        private readonly AsymmetricEncryptionService _service;
        private const string Secret = "2Yjeh9Rs/cD9tZRifvC1wgcyfNFF4B8JFO2Ou4qjiFM=";

        public AsymmetricEncryptionServiceTests()
        {
            _service = new AsymmetricEncryptionService();
        }

        [Fact]
        public void Encrypt_And_Decrypt()
        {
            // arrange
            var pair = _service.GenerateKeyPairPem();
            var secret = Encoding.UTF8.GetBytes(Secret);

            var encryptedData = _service.Encrypt(secret, pair.GetPublicKey());
            var decryptedData = _service.Decrypt(encryptedData, pair.GetPrivateKey());

            // assert
            var decryptedDataBase64 = Encoding.UTF8.GetString(decryptedData);

            Assert.Equal(Secret, decryptedDataBase64);
        }

        [Fact]
        public void Encrypt_And_Decrypt_With_External_Keys()
        {
            // arrange
            var secret = Encoding.UTF8.GetBytes(Secret);

            // act
            var privateKey =
                "-----BEGIN RSA PRIVATE KEY-----\r\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJRf+kovINZl0hF5vwA+ul/3jXBNux52Pn/u2DtbGL+0O3MwmmQW+rY5PnAKUQ7qSwnUp+UxvQpYirLMIeoELkecgcQ7PDarfSyN/aVUK8Dfq0Xat2bGmrwi5mo3spF99/y7G2LoZzy9Hwu7Bcc8HzvgWvQCHsUoxSC8Qk3z0E8fAgMBAAECgYBi6qbcH2s5mTa2USoAKdGVT7OgM9IUTtRVSeV852XVItJMyxGYD1HO0NRKsYtfRtyxOG/uISixkFx3MsFGrXQutdZB656ytH29BqGVwvak7LVlKYFJEI4rAakQQ1wlAS18kcLn5nqQsI0swM7fJLhzL09QXMUntsNODRG8VzwkmwJBAOgX2YuRkvmzrAkxm4GEAys2hj4bo5grEfYOt8iiwgt11aETEN/9aNtZVkHL0h3rsEEDTsmptN3HRdJi5mMjivUCQQCjqIfOPJejDOT62akuNcZRZKfeWdWVmmmqWhoKBZfwvew/Y/YusfrY8fJYA6ZnHt7YYKytTVS42OXWRM0N0o1DAkEAmrqRB7Zh+80dW3Znq61XciRZfr0XusdhTrR6hcHWsk6Oa2ILP/5F55DkK902vp0gK1eJ28Z4k9oujEHu7MJcowJAbRsFNChlF13t/JEbdCPZi5hv6ZE5DmbxHDwRXAO6oH6df5f5dHanO0v25VfERL8/OusdyN44eztD5C3eCTcI1wJBANPCzsThg6QODupRvf2UXYvkKIL3jzXaOJNyJe83jKpbYiRwsNMp9bV1zbvfZX1jZEOQReq1S6VqkjVpRC89vKQ=\r\n-----END RSA PRIVATE KEY-----";
            var publicKey =
                "-----BEGIN PUBLIC KEY-----\r\nMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCUX/pKLyDWZdIReb8APrpf941wTbsedj5/7tg7Wxi/tDtzMJpkFvq2OT5wClEO6ksJ1KflMb0KWIqyzCHqBC5HnIHEOzw2q30sjf2lVCvA36tF2rdmxpq8IuZqN7KRfff8uxti6Gc8vR8LuwXHPB874Fr0Ah7FKMUgvEJN89BPHwIBAw==\r\n-----END PUBLIC KEY-----\r\n";

            var encryptedData = _service.Encrypt(secret, publicKey);
            var decryptedData = _service.Decrypt(encryptedData, privateKey);

            // assert
            var decryptedDataBase64 = Encoding.UTF8.GetString(decryptedData);

            Assert.Equal(Secret, decryptedDataBase64);
        }

        [Fact]
        public void Decrypt()
        {
            // arrange
            var privateKey =
                "-----BEGIN RSA PRIVATE KEY-----\r\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKa465B3ksPWpTHtLOST9uWIlpC1Icx764/HzjWdhfRD+XMtiejMHcoaPFh+TDUDG2iLsnWsAK74/3p6+S1h+MIRFf5+2K+TpYZKMqERlqwRRxYSs7nLcWqo3ccA0xaCuXpAORG6sTZphtRba8BTkqBe3mri7gt51FPilzOrvRjNAgMBAAECgYBvJfJgT7ctOcN2nh3tt/nuWw8LI2vdp/Jf2ol5E66i1/uiHlvwiBPcEX2QVDLOAhJFsnb5HVXJ+1T8UftzlqXVn2Htx9LQ0QIh3SmiJ0UVA7WbhsY4dv+pGMdOAMFewLRJk8NDtIEEloXULllJk/DC2n6C8JwcfIEhH+Vmys3CawJBAPCri3LHMLGndK2dF8loY5toR5rJJl9f8EUCXG4g5O1YCNiXuEKfg8HaJLKgd0dbnzgB9I1upuAbTjuboNSe+2kCQQCxV45gVUWoet7Q1xYNRqjwTmUtwT65kfy+sHWRkCN0UwMJ/HPpUCvF4/FjRVquTdzfHrHslTne91P3I3im6XnFAkEAoHJc9y91y8T4c74P25rtEkWFEdtu6j/1g1boSWtDSOVbOw/QLGpX1pFtzGr6L5JqJVajCPRvQBI0J70V4xSnmwJAdjpe6uODxac/NeS5Xi8bSt7uHoDUe7aofyBOYQrCTYyssVL38OAdLpf2Qi48dDPolL8hSGN76fo3+helxJumgwJAEq9KemNpb/Zdt9SRDfIWYJyu2m14vgCt7QDwBGAsSHTde8raFbmC+31BdsmuGwOgXTC+5Ak028QJjGMKxVu3NA==\r\n-----END RSA PRIVATE KEY-----";

            var encryptedData =
                "DN3jhrbOx7hzLI0xBRV8EaDdzqHeMxJiCGddSHyQ6t/wwCuZj9GHTP0/F5nKKgBssEQ/JXjzITwgm/yduIkfmCMn+SKhOUAeOUMqdYz5p4wPd6qzRh5YAHo2eBJ4SXJbEaDgE9ZNs58RHJEk0xHOvTbGiem/dUrLqzSOfHVpr6U=";

            // act
            var decryptedData = _service.Decrypt(Convert.FromBase64String(encryptedData), privateKey);

            // assert
            Assert.Equal("8LZOlheUuPJgX2Jm/H9ueYxK3CS+R/668+D2ijzKVn4=", Convert.ToBase64String(decryptedData));
        }

        [Fact]
        public void Sign_And_Verify()
        {
            // arrange
            var data = "Test string.";

            // act
            var keyPair = _service.GenerateKeyPairPem();
            var signature = _service.GenerateSignature(Encoding.UTF8.GetBytes(data), keyPair.GetPrivateKey());
            var isValid = _service.VerifySignature(Encoding.UTF8.GetBytes(data), signature, keyPair.GetPublicKey());

            // assert
            Assert.True(isValid);
        }

        [Fact]
        public void Verify_Signature()
        {
            // arrange
            var publicKey =
                    "-----BEGIN PUBLIC KEY-----\r\nMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCUX/pKLyDWZdIReb8APrpf941wTbsedj5/7tg7Wxi/tDtzMJpkFvq2OT5wClEO6ksJ1KflMb0KWIqyzCHqBC5HnIHEOzw2q30sjf2lVCvA36tF2rdmxpq8IuZqN7KRfff8uxti6Gc8vR8LuwXHPB874Fr0Ah7FKMUgvEJN89BPHwIBAw==\r\n-----END PUBLIC KEY-----\r\n"
                ;

            var data =
                    "eyJUcmFuc2ZlckRldGFpbCI6eyJCbG9ja2NoYWluUHJvdG9jb2xJZCI6InByb3RvY29sLWlkIiwiT3BlcmF0aW9uSWQiOiJjNWY4OWE4NTI3MTE0N2M5YTBhYjFiYTZkY2FhZTVmYyIsIkJsb2NrY2hhaW5JZCI6IkV0aGVyZXVtIiwiTmV0d29ya1R5cGUiOiJ0ZXN0bmV0IiwiQXNzZXQiOnsiU3ltYm9sIjoiRVRIIiwiQXNzZXRBZGRyZXNzIjoiIiwiQXNzZXRJZCI6IiJ9LCJTb3VyY2UiOnsiQWRkcmVzcyI6ImZlNDM3ZWRiMTMyZDQ3YmE4ODdjMmM1ZWFjMzY5ZDRmIiwiQWRkcmVzc0dyb3VwIjoiQnJva2VyIEFjY291bnQgIzEiLCJOYW1lIjoiIiwiVGFnIjoiIiwiVGFnVHlwZSI6IiJ9LCJEZXN0aW5hdGlvbiI6eyJBZGRyZXNzIjoiMjU2NDI2NzJjZDdhNDQxMTk3M2ZkZTkxMjNiYTk1OWEiLCJBZGRyZXNzR3JvdXAiOiIiLCJOYW1lIjoiIiwiVGFnIjoiIiwiVGFnVHlwZSI6IiJ9LCJBbW91bnQiOiIxIiwiRmVlTGltaXQiOiIwLjAwMSIsIkNsaWVudENvbnRleHQiOnsiV2l0aGRyYXdhbFJlZmVyZW5jZUlkIjoiYWNjb3VudC03NDkyMTciLCJBY2NvdW50UmVmZXJlbmNlSWQiOiIxMjkxMSIsIlRpbWVzdGFtcCI6IjI4LjA5LjIwIDE0OjEzOjEwIiwiVXNlcklkIjoiIiwiQXBpS2V5SWQiOiJBcGkga2V5ICMzIiwiSVAiOiIxNzIuMTY0LjIwLjIifX0sIlJlc29sdXRpb24iOiJhcHByb3ZlIiwiUmVzb2x1dGlvbk1lc3NhZ2UiOiJhc2RmYXNkZiJ9"
                ;

            var signature =
                    "Kf5iSGE44iSX+UMp7lz3bYaYHE5Rpwav/wztVJHQ2E6pjNYt/muXumL7I/dyzBpWkJIGsvnrkOGMB2LiRf+M30CCWKtlZ8U0upSGz1kvlwEDP8dbpo74wcByKQy9h73dJtCuVeFbxZ/PixVUUg3IfNKfM7uExhSIIlNa4AU38Hg="
                ;

            // act
            var isValid = _service.VerifySignature(Convert.FromBase64String(data), Convert.FromBase64String(signature),
                publicKey);

            // assert
            Assert.True(isValid);
        }
    }
}
