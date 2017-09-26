using de4dot.blocks;
using de4dot.code.deobfuscators.ConfuserEx.x86;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class NativeSwitchData : SwitchData
    {
        public NativeSwitchData(Block switchBlock) : base(switchBlock)
        {
        }

        public MethodDef NativeMethodDef;

        public override bool Initialize()
        {
            var instr = _block.Instructions;
            if (instr.Count <= 4)
                return false;

            if (instr[0].IsLdcI4() && instr[1].OpCode == OpCodes.Call)
            {
                IsKeyHardCoded = true;
                Key = instr[0].GetLdcI4Value();
            }

            if (!IsKeyHardCoded && instr[0].OpCode != OpCodes.Call)
                return false;

            var nativeMethodDef = _block.Instructions[IsKeyHardCoded ? 1 : 0].Operand as MethodDef;

            if (nativeMethodDef == null || !nativeMethodDef.IsStatic || !nativeMethodDef.IsNative)
                return false;
            if (!DotNetUtils.IsMethod(nativeMethodDef, "System.Int32", "(System.Int32)"))
                return false;
            for (var i = IsKeyHardCoded ? 2 : 1; i < instr.Count - 1; i++)
                if (!instr[i].IsValidInstr())
                    return false;

            NativeMethodDef = nativeMethodDef;
            return true;
        }
    }
}
