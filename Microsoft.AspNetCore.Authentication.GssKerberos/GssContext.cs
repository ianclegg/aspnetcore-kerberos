using System;
using System.Reflection;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.AspNetCore.Authentication.GssKerberos.Disposables;
using Microsoft.AspNetCore.Authentication.GssKerberos.Native;

namespace Microsoft.AspNetCore.Authentication.GssKerberos
{
    public class GssContext
    {
        public static Encoding iso8859 = Encoding.GetEncoding("iso-8859-1");

        public static void main()
        {

            var acceptor = new GssAcceptor("HTTP/orion.testweb.bp.com", 0);
            var token = new byte[1];
            acceptor.Accept(token);

            //if(acceptor.)

        }
    }
}