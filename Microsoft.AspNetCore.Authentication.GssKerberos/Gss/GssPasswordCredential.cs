using System;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;

using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.Krb5Interop;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    internal class GssPasswordCredential : GssCredential
    {
        private IntPtr _credentials;
        private IntPtr _gssUsername;

        protected internal override IntPtr Credentials => _credentials;

        public GssPasswordCredential(string principal, string password, CredentialUsage usage)
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            // copy the principal name to a gss_buffer
            using (var gssUsernameBuffer = GssBuffer.FromString(principal))
            using (var gssPasswordBuffer = GssBuffer.FromString(password))
            {
                // use the buffer to import the name into a gss_name
                majorStatus = gss_import_name(
                    out minorStatus,
                    ref gssUsernameBuffer.Value,
                    ref GssNtPrincipalName,
                    out _gssUsername
                );
                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS provider was unable to import the supplied principal name",
                        majorStatus, minorStatus, GssNtHostBasedService);

                // allocate storage for the actual mech oid
                var actualMechanims = default(GssOidDesc);

                majorStatus = gss_acquire_cred_with_password(
                    out minorStatus,
                    _gssUsername,
                    ref gssPasswordBuffer.Value,
                    0,
                    ref GssSpnegoMechOidSet,
                    (int)usage,
                    ref _credentials,
                    ref actualMechanims,
                    out var actualExpiry);

                if (majorStatus != GSS_S_COMPLETE)
                    throw new GssException("The GSS Provider was unable aquire credentials for authentication",
                        majorStatus, minorStatus, GssSpnegoMechOidDesc);
            }
        }

        public override void Dispose()
        {
            uint minorStatus = 0;
            uint majorStatus = 0;

            majorStatus = gss_release_name(out minorStatus, ref _gssUsername);
            if (majorStatus != GSS_S_COMPLETE)
            {
                throw new GssException("The GSS provider was unable to release the princpal name handle",
                    majorStatus, minorStatus, GssNtHostBasedService);
            }

            majorStatus = gss_release_cred(out minorStatus, ref _credentials);
            if (majorStatus != GSS_S_COMPLETE)
            {
                throw new GssException("The GSS provider was unable to release the credential handle",
                    majorStatus, minorStatus, GssNtHostBasedService);
            }
        }
    }
}