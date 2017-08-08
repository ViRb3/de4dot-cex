using System.Collections.Generic;
using de4dot.Bea;
using de4dot.code.deobfuscators.ConfuserEx.x86;

namespace ConfuserDeobfuscator.Engine.Routines.Ex.x86.Instructions
{
    class X86IMUL : X86Instruction
    {
        public X86IMUL(Disasm rawInstruction) : base()
        {
            Operands = new IX86Operand[3];
            Operands[0] = GetOperand(rawInstruction.Argument1);
            Operands[1] =GetOperand( rawInstruction.Argument2);
            Operands[2] = GetOperand(rawInstruction.Argument3);
        }

        public override X86OpCode OpCode { get { return X86OpCode.IMUL; } }

        public override void Execute(Dictionary<string, int> registers, Stack<int> localStack)
        {
            var source = ((X86RegisterOperand) Operands[0]).Register.ToString();
            var target1 = ((X86RegisterOperand) Operands[1]).Register.ToString();

            if (Operands[2] is X86ImmediateOperand)
                registers[source] = registers[target1]*((X86ImmediateOperand) Operands[2]).Immediate;
            else
                registers[source] = registers[target1]*registers[((X86RegisterOperand) Operands[2]).Register.ToString()];
        }
    }
}
