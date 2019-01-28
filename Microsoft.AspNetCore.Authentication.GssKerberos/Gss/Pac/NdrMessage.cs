namespace Microsoft.AspNetCore.Authentication.GssKerberos.Pac
{
    public abstract class NdrMessage : NdrObject
    {
        public RpcHeader Header { get; }

        protected NdrMessage(byte[] data) : base(data)
        {
            if ((data?.Length ?? 0) <= 0)
                return;

            Header = Stream.ReadNdrHeader();
        }
    }

    public abstract class NdrObject
    {
        protected NdrBinaryReader Stream { get; }

        protected NdrObject(byte[] data)
            => Stream = new NdrBinaryReader(data);


        protected NdrObject(NdrBinaryReader stream)
            => Stream = stream;
    }
}