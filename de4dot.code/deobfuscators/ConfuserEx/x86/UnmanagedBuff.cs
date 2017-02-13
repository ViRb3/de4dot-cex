using System;
using System.Runtime.InteropServices;

namespace de4dot.code.x86
{
    public class UnmanagedBuffer
    {
        public readonly IntPtr Ptr = IntPtr.Zero;
        public readonly int Length = 0;

        public UnmanagedBuffer(byte[] data)
        {
            Ptr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, Ptr, data.Length);
            Length = data.Length;
        }
    }
}
