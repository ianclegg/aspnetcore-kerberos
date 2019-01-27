using System;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public enum CredentialUsage
    {
        Both = 0,
        Initiate = 1,
        Accept = 2
    }

    public static class GssCredentials
    {
        /// <summary>
        /// Aquires credentials for the supplied principal using the supplied password
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="usage"></param>
        /// <returns></returns>
        public static GssCredential FromPassword(string username, string password, CredentialUsage usage = CredentialUsage.Both)
        {
            return new GssPasswordCredential(username, password, usage);
        }

        /// <summary>
        /// Aquires credentials for the supplied principal using material stored in a valid keytab
        /// </summary>
        /// <param name="keytab"></param>
        /// <param name="username"></param>
        /// <param name="usage"></param>
        /// <returns></returns>
        public static GssCredential FromKeytab(string username,
            CredentialUsage usage = CredentialUsage.Both,
            string keytab = null)
        {       
            return new GssKeytabCredential(username, keytab, usage);
        }

        /// <summary>
        /// Aquires default credentials (feeling lucky)
        /// </summary>
        /// <returns></returns>
        //public static GssCredential Default()
        //{
        //    throw new NotImplementedException();
        //}
    }

    public abstract class GssCredential : IDisposable
    {
        protected internal abstract IntPtr Credentials { get; }

        public abstract void Dispose();
    }
}
