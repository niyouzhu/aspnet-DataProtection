// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;

namespace Microsoft.AspNetCore.DataProtection
{
    internal class RegistryPolicy
    {
        public RegistryPolicy(
            IAuthenticatedEncryptorConfiguration configuration,
            IEnumerable<IKeyEscrowSink> keyEscrowSinks,
            int? defaultKeyLifetime)
        {
            EncryptorConfiguration = configuration;
            KeyEscrowSinks = KeyEscrowSinks;
            DefaultKeyLifetime = defaultKeyLifetime;
        }

        public IAuthenticatedEncryptorConfiguration EncryptorConfiguration { get; }

        public IEnumerable<IKeyEscrowSink> KeyEscrowSinks { get; }

        public int? DefaultKeyLifetime { get; }
    }
}
