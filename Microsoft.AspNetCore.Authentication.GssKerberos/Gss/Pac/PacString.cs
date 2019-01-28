using System.IO;

namespace Microsoft.AspNetCore.Authentication.GssKerberos.Pac
{
    public class PacString
    {
        private readonly short length;
        private readonly short maxLength;
        private readonly int pointer;

        public PacString(short length, short maxLength, int pointer)
        {
            this.length = length;
            this.maxLength = maxLength;
            this.pointer = pointer;
        }

        public string ReadString(NdrBinaryReader reader)
        {
            if (pointer == 0)
                return null;

            var result = reader.ReadString(maxLength);
            var expected = length / 2;

            if (result.Length != expected)
                throw new InvalidDataException($"Read length {result.Length} doesn't match expected length {expected}");

            return result;
        }
    }
}
