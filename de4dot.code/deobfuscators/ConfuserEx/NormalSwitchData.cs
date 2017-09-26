using de4dot.blocks;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class NormalSwitchData : SwitchData
    {
        public readonly Block Block;
        public NormalSwitchData(Block switchBlock) : base(switchBlock)
        {
            Block = switchBlock;
        }

        public int DivisionKey;

        public override bool Initialize()
        {
            var instr = _block.Instructions;
            if (instr.Count != 7)
                return false;

            if (!instr[0].IsLdcI4())
                return false;
            if (instr[1].OpCode != OpCodes.Xor)
                return false;
            if (instr[2].OpCode != OpCodes.Dup)
                return false;
            if (!instr[3].IsStloc())
                return false;
            if (!instr[4].IsLdcI4())
                return false;
            if (instr[5].OpCode != OpCodes.Rem_Un)
                return false;

            Key = instr[0].GetLdcI4Value();
            DivisionKey = instr[4].GetLdcI4Value();
            return true;
        }
    }
}
