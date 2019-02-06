using System;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class SspiCredentials : IDisposable
    {
        private const string SecurityPackage = "Negotiate";
        private readonly SecurityHandle _credentials;

        public SspiCredentials()
        {
            long expiry = 0;

            var result = SspiInterop.AcquireCredentialsHandle(
                IntPtr.Zero, 
                SecurityPackage,
                SspiInterop.SECPKG_CRED_BOTH,
                IntPtr.Zero,
                IntPtr.Zero,
                0,
                IntPtr.Zero,
                ref _credentials,
                ref expiry);

            if (result != SspiInterop.SEC_E_OK)
            {
                throw new Exception($"Unable to aquire credentials for current user,  SECURITY_STATUS 0x{result:x8}");
            }

            Credentials = _credentials;
        }

        public SspiCredentials(string principal, string username, string password, string domain)
        {
            long expiry = 0;

            var authenticationData = new SEC_WINNT_AUTH_IDENTITY
            {
                User = username,
                UserLength = username.Length,
                Domain = domain,
                DomainLength = domain.Length,
                Password = password,
                PasswordLength = password.Length,
                Flags = SspiInterop.SEC_WINNT_AUTH_IDENTITY_UNICODE
            };

            var result = SspiInterop.AcquireCredentialsHandle(
                principal,
                SecurityPackage,
                SspiInterop.SECPKG_CRED_BOTH,
                IntPtr.Zero,
                authenticationData,
                0,
                IntPtr.Zero,
                ref _credentials,
                ref expiry);

            if (result != SspiInterop.SEC_E_OK)
            {
                throw new Exception($"Unable to aquire credentials for {principal},  SECURITY_STATUS 0x{result:x8}");
            }
            Credentials = _credentials;
        }

        protected internal SecurityHandle Credentials { get; }

        public void Dispose()
        {
            // TODO: Realease credentials when disposed
        }
    }
}
