using System.Text;
using Microsoft.AspNetCore.Authentication.GssKerberos.Gss;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssContext
    {
        public static Encoding iso8859 = Encoding.GetEncoding("iso-8859-1");

        public static void main()
        {
            using (var clientCredentials = GssCredentials.FromPassword("<username>", "<password>"))
            using (var serverCredentials = GssCredentials.FromKeytab("<service>", CredentialUsage.Accept))
            {
                using (var initiator = new GssInitiator(credential: clientCredentials, spn: "<service>"))
                using (var acceptor = new GssAcceptor(credential: serverCredentials))
                {
                    var token = initiator.Initiate(null);
                    acceptor.Accept(token);
                }                
            }
        }
    }
}