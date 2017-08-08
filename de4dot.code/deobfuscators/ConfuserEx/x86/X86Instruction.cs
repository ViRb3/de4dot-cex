using System.Collections.Generic;
using System.Globalization;
using de4dot.Bea;

namespace de4dot.code.deobfuscators.ConfuserEx.x86
{
    public enum X86OpCode
    {
        MOV,
        ADD,
        SUB,
        IMUL,
        DIV,
        NEG,
        NOT,
        XOR,
        POP,
        PUSH
    }

    public enum X86Register
    {
        EAX = 537001985,
        ECX = 537001986,
        EDX = 537001988,
        EBX = 537001992,
        ESP = 537001989,
        EBP = 537001990,
        ESI = 537002048,
        EDI = 537002112
    }

    public interface IX86Operand
    {
    }

    public class X86RegisterOperand : IX86Operand
    {
        public X86Register Register { get; set; }

        public X86RegisterOperand(X86Register reg)
        {
            Register = reg;
        }
    }

    public class X86ImmediateOperand : IX86Operand
    {
        public int Immediate { get; set; }

        public X86ImmediateOperand(int imm)
        {
            Immediate = imm;
        }
    }

    public abstract class X86Instruction
    {
        public abstract X86OpCode OpCode { get; }
        public IX86Operand[] Operands { get; set; }
        public abstract void Execute(Dictionary<string, int> registers, Stack<int> localStack);

        public static IX86Operand GetOperand(ArgumentType argument)
        {
            if (argument.ArgType == -2013265920)
                return
                    new X86ImmediateOperand(int.Parse(argument.ArgMnemonic.TrimEnd('h'),
                        NumberStyles.HexNumber));
            return new X86RegisterOperand((X86Register)argument.ArgType);
        }
    }
}
