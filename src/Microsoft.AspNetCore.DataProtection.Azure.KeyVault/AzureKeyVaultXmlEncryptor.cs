// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace Microsoft.AspNetCore.DataProtection.Azure.KeyVault
{
    internal class AzureKeyVaultXmlEncryptor: IXmlEncryptor
    {
        private readonly IKeyVaultEncryptionClient _client;
        private readonly string _keyId;
        private readonly string _algorithm;

        public AzureKeyVaultXmlEncryptor(IKeyVaultEncryptionClient client, string keyId, string algorithm)
        {
            _client = client;
            _keyId = keyId;
            _algorithm = algorithm;
        }

        public EncryptedXmlInfo Encrypt(XElement plaintextElement)
        {
            return EncryptAsync(plaintextElement).GetAwaiter().GetResult();
        }

        private async Task<EncryptedXmlInfo> EncryptAsync(XElement plaintextElement)
        {
            using (var memoryStream = new MemoryStream())
            {
                plaintextElement.Save(memoryStream);
                var result = await _client.EncryptAsync(_keyId, _algorithm, memoryStream.ToArray());

                var element = new XElement("encryptedKey",
                    new XComment(" This key is encrypted with Azure KeyVault."),
                    new XComment(" Kid: " + result.Kid),
                    new XElement("value", Convert.ToBase64String(result.Result)));

                return new EncryptedXmlInfo(element, typeof(AzureKeyVaultXmlDecryptor));
            }
        }
    }
}
