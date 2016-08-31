// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace Microsoft.AspNetCore.DataProtection.Azure.KeyVault
{
    internal class AzureKeyVaultXmlDecryptor: IXmlDecryptor
    {
        private readonly IKeyVaultEncryptionClient _client;
        private readonly string _keyId;
        private readonly string _algorithm;

        public AzureKeyVaultXmlDecryptor(IKeyVaultEncryptionClient client, string keyId, string algorithm)
        {
            _client = client;
            _keyId = keyId;
            _algorithm = algorithm;
        }
        
        public XElement Decrypt(XElement encryptedElement)
        {
            return DecryptAsync(encryptedElement).GetAwaiter().GetResult();
        }

        private async Task<XElement> DecryptAsync(XElement encryptedElement)
        {
            var protectedSecret = Convert.FromBase64String((string)encryptedElement.Element("value"));

            var result = await _client.DecryptAsync(_keyId, _algorithm, protectedSecret);
            using (var memoryStream = new MemoryStream(result.Result))
            {
                return XElement.Load(memoryStream);
            }
        }
    }
}