using System.IO;
using System.Runtime.InteropServices;

namespace de4dot.Bea
{
    public static class BeaEngine
    {
        static BeaEngine()
        {
            if(!File.Exists("BeaEngine.dll"))
            {
                throw new FileNotFoundException("BeaEngine.dll missing!");
            }
        }

        [DllImport("BeaEngine.dll")]
        public static extern int Disasm([In, Out, MarshalAs(UnmanagedType.LPStruct)] Disasm disasm);

        [DllImport("BeaEngine.dll")]
        private static extern string BeaEngineVersion();

        [DllImport("BeaEngine.dll")]
        private static extern string BeaEngineRevision();

        public static string Version
       {
            get
            {
                return BeaEngineVersion();
            }
        }

        public static string Revision
        {
            get
            {
                return BeaEngineRevision();
            }
        }
    }
}
