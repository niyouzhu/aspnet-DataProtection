// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;

namespace Microsoft.AspNetCore.DataProtection.Azure.KeyVault
{
    internal class KeyVaultClientWrappers : IKeyVaultEncryptionClient
    {
        private readonly KeyVaultClient _client;

        public KeyVaultClientWrappers(KeyVaultClient client)
        {
            _client = client;
        }

        public Task<KeyOperationResult> DecryptAsync(string keyIdentifier, string algorithm, byte[] cipherText)
        {
            return _client.DecryptAsync(keyIdentifier, algorithm, cipherText);
        }

        public Task<KeyOperationResult> EncryptAsync(string keyIdentifier, string algorithm, byte[] cipherText)
        {
            return _client.EncryptAsync(keyIdentifier, algorithm, cipherText);
        }
    }
}