using System;
using System.Runtime.InteropServices;

namespace de4dot.code.deobfuscators.ConfuserEx.x86
{
    public class UnmanagedBuffer
    {
        public readonly IntPtr Ptr;
        public readonly int Length;

        public UnmanagedBuffer(byte[] data)
        {
            Ptr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, Ptr, data.Length);
            Length = data.Length;
        }
    }
}
