using System.Collections.Generic;
using de4dot.Bea;
using de4dot.code.deobfuscators.ConfuserEx.x86;

namespace ConfuserDeobfuscator.Engine.Routines.Ex.x86.Instructions
{
    class X86ADD : X86Instruction
    {
        public X86ADD(Disasm rawInstruction) : base()
        {
            Operands = new IX86Operand[2];
            Operands[0] = GetOperand(rawInstruction.Argument1);
            Operands[1] = GetOperand(rawInstruction.Argument2);
        }

        public override X86OpCode OpCode { get { return X86OpCode.ADD; } }

        public override void Execute(Dictionary<string, int> registers, Stack<int> localStack)
        {
            if (Operands[1] is X86ImmediateOperand)
                registers[((X86RegisterOperand) Operands[0]).Register.ToString()] +=
                    ((X86ImmediateOperand) Operands[1]).Immediate;
            else
                registers[((X86RegisterOperand) Operands[0]).Register.ToString()] +=
                    registers[((X86RegisterOperand) Operands[1]).Register.ToString()];
        }
    }
}
