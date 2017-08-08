using System.Collections.Generic;
using de4dot.Bea;
using de4dot.code.deobfuscators.ConfuserEx.x86;

namespace ConfuserDeobfuscator.Engine.Routines.Ex.x86.Instructions
{
    class X86DIV : X86Instruction
    {
        public X86DIV(Disasm rawInstruction) : base()
        {
            Operands = new IX86Operand[2];
            Operands[0] = GetOperand(rawInstruction.Argument1);
            Operands[1] = GetOperand(rawInstruction.Argument2);
        }

        public override X86OpCode OpCode { get { return X86OpCode.DIV; } }

        public override void Execute(Dictionary<string, int> registers, Stack<int> localStack)
        {
            
        }
    }
}
