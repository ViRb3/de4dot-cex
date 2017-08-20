using System.IO;
using System.Runtime.InteropServices;

namespace de4dot.Bea
{
    public static class BeaEngine
    {
        // 'de4dot\bin\de4dot.blocks.dll' -> 'de4dot\bin\'
        private static string _executingPath = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);

        static BeaEngine()
        {
            if (!File.Exists(Path.Combine(_executingPath, "BeaEngine.dll")))
            {
                throw new FileNotFoundException("BeaEngine.dll missing!");
            }

            //TODO: Better handle native DLL discovery
            SetDllDirectory(_executingPath);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool SetDllDirectory(string lpPathName);

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
