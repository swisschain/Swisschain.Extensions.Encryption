using System;
using Xunit;

namespace Swisschain.Extensions.Encryption.Tests
{
    public class SymmetricEncryptionServiceTests
    {
        private readonly SymmetricEncryptionService _service;

        public SymmetricEncryptionServiceTests()
        {
            _service = new SymmetricEncryptionService("2Yjeh9Rs/cD9tZRifvC1wgcyfNFF4B8JFO2Ou4qjiFM=");
        }

        [Fact]
        public void Encrypt_And_Decrypt()
        {
            var data = "Test string to encrypt.";

            var encryptedData = _service.Encrypt(data);
            var decryptedData = _service.Decrypt(encryptedData);

            Assert.Equal(data, decryptedData);
        }

        [Fact]
        public void Decrypt()
        {
            // arrange
            var key = Convert.FromBase64String("Sbu9VBzfZPhrZDbUJ+5iH7zM1FW22eVwZ6f9rkiGnVU=");
            var nonce = Convert.FromBase64String("zcK58atDZhXgXcqs5DdTIA==");
            var encryptedData = "CjjckdqhNsUuC2tpxUMveEi+2ewnheU05ZeM4Xcdxvg+OMjg+K1ymW85kDlxltvAJC3ylC+5eivOH5fnOhfqwM11/1Oqa0QYtzM+uSkBoeuE+UnRny1yWN9qv7m2gL9qvXhxgsLE7bxkvsYjihkDILsMYFwxE2qNXBOoRG1s8uwbekq9CjFdrVrxtj26+TgSoOyNQDwxotgauUK2eTjOJoDpG0fcvgyBryaFsUA7f9s75Xjc3dJf3ZLKU/GXljvkDIxwzE6gtp7yfH76x7icd05EKgF+lKQawtZkoQMTGMk8h2vBoL+fzXPJlXhaYFUh0Y+MWk3YBieTJlV9Pa4yfh0JXrnsx8wmdqhtXCPBEW8OmHIEuqXHwcVj2u9bmu/+a+bOQ9te+UVOFoqXULr1d6QDS1fW4EK6KTkQYbMwZDrBBIb+NDonP6QDek8nvdcuqJSyKULyT39syyojxcEJX75CnRd4oB/iDEaKft822Cm7nzNeL04iIwrFxILjXrezArRadYZ02pACO+wc+WsWs8iXH5XTcNAOxmmfOaJvCY0LSeyEVDjVnW+ebR0t6gS5cy3meaBE+BLqswYGxzSbrgqkaDT49mfCWVvnPMGCY4lKPw9uYuH4bbwawsjVrLguA78yGabc9uhtHHlgzBgFuyXfb6b0yLrq0zn7P8BCeXEdSwcHE1sbnnNckx75NhEMP7AvGbNUmxTg1VikkivIbPb8Jtl2S4WjfEW7y2/GC8mCSoofaeKF67GatbmSWcvba0Usv/kbNZOVs/hKsSAlKXLSygMoWg9hsFhImmisfFFchFPwjmdoIorZ0dgVOJSsc4oqERX9kS7tA9tEZ7xCdWnqSl5cBFAUpTyICHuyMgpYNgmHu8sck9mqV6tNCfMi9rzfyk25dzNwuQHmT6xeB3lFlML4PgSRHO/7vhqiRCd2vkyIr2CYh1M+Uwq9aSviLNRgq3rkUfdGn1oJCx7qbg==";

            // act
            var decryptedData = _service.Decrypt(encryptedData, key, nonce);

            // assert
            Assert.Equal(
                "{\"amount\":\"3.9812\",\"asset\":{\"assetAddress\":\"0x3A9BC420a42D4386D1A84CC560e7324779D86734\",\"assetId\":\"100001\",\"symbol\":\"ETH\"},\"blockchainId\":\"ethereum-ropsten\",\"blockchainProtocolId\":\"ethereum\",\"clientContext\":{\"userId\":\"1000045\",\"apiKeyId\":\"4000762\",\"accountReferenceId\":\"Mr. White\",\"withdrawalReferenceId\":\"Mr. Red\",\"ip\":\"10.0.25.179\",\"timestamp\":\"2020-09-30T12:34:22.425645700Z\"},\"destination\":{\"address\":\"0x1A9BC420a42D4386D1A84CC560e7324779D86734\",\"name\":\"No name\",\"group\":\"1000457\",\"tag\":\"this is a text tag value\",\"tagType\":\"text\"},\"feeLimit\":\"0.657\",\"networkType\":\"test\",\"operationId\":\"D2B5B7E5-15CF-44C8-8C3E-361B421DE671\",\"source\":{\"address\":\"0x4A9BC420a42D4386D1A84CC560e7324779D86734\",\"name\":null,\"group\":\"1000458\"}}",
                decryptedData);
        }

        [Fact]
        public void Decrypt_External()
        {
            // arrange
            var key = Convert.FromBase64String("uL6FPG4k5UFHstWYuDySJl4Y6NOH2/4WaC/7iDSelCk=");
            var nonce = Convert.FromBase64String("NwWJ5vtVL2fRmJP+nnrZaQ==");
            var originValue =
                "{\"amount\":\"3.9812\",\"asset\":{\"assetAddress\":\"0x3A9BC420a42D4386D1A84CC560e7324779D86734\",\"assetId\":\"100001\",\"symbol\":\"ETH\"},\"blockchainId\":\"ethereum-ropsten\",\"blockchainProtocolId\":\"ethereum\",\"clientContext\":{\"userId\":\"1000045\",\"apiKeyId\":\"4000762\",\"accountReferenceId\":\"Mr. White\",\"withdrawalReferenceId\":\"Mr. Red\",\"ip\":\"10.0.25.179\",\"timestamp\":\"2020-09-30T13:41:12.209060300Z\"},\"destination\":{\"address\":\"0x1A9BC420a42D4386D1A84CC560e7324779D86734\",\"name\":\"No name\",\"group\":\"1000457\",\"tag\":\"this is a text tag value\",\"tagType\":\"text\"},\"feeLimit\":\"0.657\",\"networkType\":\"test\",\"operationId\":\"D2B5B7E5-15CF-44C8-8C3E-361B421DE671\",\"source\":{\"address\":\"0x4A9BC420a42D4386D1A84CC560e7324779D86734\",\"name\":null,\"group\":\"1000458\"}}";
            var encryptedOriginValue =
                "29U6B+E/y3QK+M2ZHHd1D3V2v5R3E9O6zuj4o6gToeTC/G/wTLqSSf6jYWSpnNgcvvGZCg+F1bgWxlHuaj9OHRaSzBuhugSDIb5sicKPjPboaXVRxQWh9ZaK14vcv1JtQG2uA/vWUSEMgPCi78KL8albDXNQQq/H25bIjCyHxCaQ1Oxb6XvCkJFop/6C6qn3mHE9m7lfJRJvGgaz+F/YTa6vgqWf7ejfsjaPzd+U17sV+gQJO7NoG5N3cDTT7K98fNMKIgVNSFjkN/gOrjuakkzums/+oflrMVPTkUezBSDASjOYT7LiQv1tJBZzTtNYRUllCXriQAyXXr9SAsmPxpYHdug0imqNjW+00N2u7d1tAPl7KHSXoH40hdCssatXynCv4A8ercarSrqRBbV9crI7Y4nXOuP6BmfMd2i28R2Y0HffSpt1w5sEC95vZjNJHzd10uMCXuvKcJcTvfplA+BC8B8CUCnLfu/GV+sq7Vo671m0wS2ECPrPMfCBniJAedV4G7lnYNYjfyM9sudVIhUWut6rPV4K/PTYDVHTSMLGh9PRZzljuLO83bwoIYOVTi6zQ1kcGBAwVCzsEVtLkxy1IAXo97r3A3c/n0IScwECwXzzSFbX76x9WHbBB5zP/mmq4kZVJyi7es7cTvLAApL9ph8ZdWR/UHaTiiFsPf5pZq1L+6DTVXxCeHFw9qKjaKqZhZVdcuvR1MDq9ag1lbQkNJINVHgW0N3bIARCOyZ0MkIo8VlcbHDgBMbquvzjZslB08FhGdmETeuQ7giWXbedrTtYQgDXUVbX0c8l37C6d/j2MrtH8ln44PFV+CjBhexILtmBkztkseoeayMbU6xm6dJVmdBodS8KyGGFnYiLACGGPnoyl78EWm7N7dxMdRHS4S++qbPsNFPVNCKsqf7T8zSgk9onRtJkwBM2zB4P9HnFNK1yCbRZ4bTHrhLIqXFI8yhRHiml3q6Y7NCIog==";

            // act
            var decryptedData = _service.Decrypt(encryptedOriginValue, key, nonce);

            // assert
            Assert.Equal(originValue, decryptedData);
        }
    }
}
