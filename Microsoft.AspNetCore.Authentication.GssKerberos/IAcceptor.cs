using System;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{

    public interface IAcceptor : IDisposable
    {
        /// <summary>
        /// Indicates that the context exchange was successful and that the identity of the client has been aquired
        /// </summary>
        bool IsEstablished { get; }

        /// <summary>
        /// The Kerberos Principal that was aquired during the context exchange
        /// </summary>
        string Principal { get; }

        /// <summary>
        /// The Security Identifiers (SID's) of the groups to which the principal belongs in ActiveDirectory
        /// </summary>
        string[] Roles { get; }

        /// <summary>
        /// Called each time the client submits authentication material until the context exchange is complete
        /// </summary>
        /// <param name="token">The authentication data supplied by the client</param>
        /// <returns>The autentication data to to be passed to the client</returns>
        byte[] Accept(byte[] token);
    }
}
