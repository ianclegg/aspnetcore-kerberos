using System;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Sspi
{
    public class SspiCredentials
    {
        private readonly SecurityHandle _credentials;

        public SspiCredentials(string principal, string password)
        {
            long expiry = 0;
            var authData = new SafeSspiAuthDataHandle();

            var result = SspiInterop.AcquireCredentialsHandle(
                null,
                "Negotiate",
                3,
                IntPtr.Zero,
                authData,
                0,
                IntPtr.Zero,
                ref _credentials,
                ref expiry);

            
            Credentials = _credentials;

        }
        protected internal SecurityHandle Credentials { get; }

    }
}
