using System.Text;
using static Microsoft.AspNetCore.Authentication.GssKerberos.Native.NativeMethods;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Disposables
{
    internal static class GssBuffer
    {
        private static readonly Encoding iso8859 = Encoding.GetEncoding("iso-8859-1");
        
        internal static Disposable<GssBufferDescStruct> FromString(string buffer) =>
            Disposable.From(
                Pinned.From(iso8859.GetBytes(buffer)), p => new GssBufferDescStruct {
                    length = (uint)p.Value.Length,
                    value = p.Address});
    }
}