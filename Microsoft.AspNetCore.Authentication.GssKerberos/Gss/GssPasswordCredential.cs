using System;
using System.Runtime.InteropServices;
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

                var oids = new GssOidDesc[GssSpnegoMechOidSet.count];
                var sizeOfOid = Marshal.SizeOf(typeof(GssOidDesc));
                for (var i = 0; i < GssSpnegoMechOidSet.count; i++)
                {
                    oids[i] = Marshal.PtrToStructure<GssOidDesc>(GssSpnegoMechOidSet.elements + sizeOfOid * i);
                }
                foreach (var mechanism in oids)
                {
                    var mechBytes = new byte[mechanism.length];
                    Marshal.Copy(mechanism.elements, mechBytes, 0, (int)mechanism.length);
                    Console.WriteLine("Requesting Credential Mechanism: " + BitConverter.ToString(mechBytes));
                }

                var actualMechanimsPtr = IntPtr.Zero;
                majorStatus = gss_acquire_cred_with_password(
                    out minorStatus,
                    _gssUsername,
                    ref gssPasswordBuffer.Value,
                    0,
                    ref GssSpnegoMechOidSet,
                    (int)usage,
                    ref _credentials,
                    ref actualMechanimsPtr,
                    out var actualExpiry);

                if (actualMechanimsPtr != IntPtr.Zero)
                {
                    var actualMechanims = Marshal.PtrToStructure<GssOidSet>(actualMechanimsPtr);
                    Console.WriteLine("Got credentials for " + actualMechanims.count + "mechanisms");
                    var actualOids = new GssOidDesc[actualMechanims.count];
                    for (var i = 0; i < actualMechanims.count; i++)
                    {
                        actualOids[i] = Marshal.PtrToStructure<GssOidDesc>(actualMechanims.elements + sizeOfOid * i);
                    }

                    foreach (var mechanism in actualOids)
                    {
                        var mechBytes = new byte[mechanism.length];
                        Marshal.Copy(mechanism.elements, mechBytes, 0, (int) mechanism.length);
                        Console.WriteLine("Got Credential for Mechanism" + BitConverter.ToString(mechBytes));
                    }
                }
                else
                {
                    Console.WriteLine("Got no mechs");
                }

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