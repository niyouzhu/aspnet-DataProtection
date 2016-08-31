// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;
using Moq;
using Xunit;

namespace Microsoft.AspNetCore.DataProtection.Azure.KeyVault.Test
{
    public class AzureKeyVaultTests
    {
        [Fact]
        public void UsesKeyVaultToEncryptKey()
        {
            var mock = new Mock<IKeyVaultEncryptionClient>();
            mock.Setup(client => client.EncryptAsync("key", JsonWebKeyEncryptionAlgorithm.RSAOAEP, It.IsAny<byte[]>()))
                .Returns<string, string, byte[]>((_, __, data) => Task.FromResult(new KeyOperationResult() { Result = data }));

            var encryptor = new AzureKeyVaultXmlEncryptor(mock.Object, "key", JsonWebKeyEncryptionAlgorithm.RSAOAEP);
            var result = encryptor.Encrypt(new XElement("Element"));
            var value = result.EncryptedElement.Element("value");

            mock.VerifyAll();
            Assert.NotNull(result);
            Assert.NotNull(value);
            Assert.Equal(typeof(AzureKeyVaultXmlDecryptor), result.DecryptorType);
            Assert.Equal("77u/PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjxFbGVtZW50IC8+", value.Value);
        }

        [Fact]
        public void UsesKeyVaultToDecryptKey()
        {
            var mock = new Mock<IKeyVaultEncryptionClient>();
            mock.Setup(client => client.DecryptAsync("key", JsonWebKeyEncryptionAlgorithm.RSAOAEP, It.IsAny<byte[]>()))
                .Returns<string, string, byte[]>((_, __, data) => Task.FromResult(new KeyOperationResult() { Result = data }));

            var encryptor = new AzureKeyVaultXmlDecryptor(mock.Object, "key", JsonWebKeyEncryptionAlgorithm.RSAOAEP);
            var result = encryptor.Decrypt(XElement.Parse(
@"<encryptedKey>
     <value>77u/PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjxFbGVtZW50IC8+</value>
</encryptedKey>"));

            Assert.NotNull(result);
            Assert.Equal("<Element />", result.ToString());
        }
    }
}
