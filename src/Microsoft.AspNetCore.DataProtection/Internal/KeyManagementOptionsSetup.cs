// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.DataProtection.Internal
{
    internal class KeyManagementOptionsSetup : IConfigureOptions<KeyManagementOptions>
    {
        private readonly RegistryPolicyResolver _registryPolicyResolver;
        private readonly ILoggerFactory _loggerFactory;

        public KeyManagementOptionsSetup(ILoggerFactory loggerFactory) : this(loggerFactory, registryPolicyResolver: null)
        {
        }

        public KeyManagementOptionsSetup(ILoggerFactory loggerFactory, RegistryPolicyResolver registryPolicyResolver)
        {
            _loggerFactory = loggerFactory;
            _registryPolicyResolver = registryPolicyResolver;
        }

        public void Configure(KeyManagementOptions options)
        {
            RegistryPolicyContext context = null;
            if (_registryPolicyResolver != null)
            {
                context = _registryPolicyResolver.ResolvePolicy();
            }

            DataProtectionProviderFactory.PopulateDefaultOptions(options, context: context, loggerFactory: _loggerFactory);
        }
    }
}
