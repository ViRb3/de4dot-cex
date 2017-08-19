using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using ConfuserDeobfuscator.Engine.Routines.Ex.x86;
using ConfuserDeobfuscator.Engine.Routines.Ex.x86.Instructions;
using de4dot.Bea;
using dnlib.DotNet;

namespace de4dot.code.deobfuscators.ConfuserEx.x86
{
    public sealed class X86Method
    {
        public List<X86Instruction> Instructions;

        public Stack<int> LocalStack = new Stack<int>();
        public Dictionary<string, int> Registers = new Dictionary<string, int>
        {
            {"EAX", 0},
            {"EBX", 0},
            {"ECX", 0},
            {"EDX", 0},
            {"ESP", 0},
            {"EBP", 0},
            {"ESI", 0},
            {"EDI", 0}
        };

        private readonly ModuleDefMD _module;
        public X86Method(MethodDef method,ModuleDefMD module)
        {
            this._module = module;
            Instructions = new List<X86Instruction>();
            ParseInstructions(method);
        }

        private void ParseInstructions(MethodDef method)
        {
            var rawInstructions = new List<Disasm>();

            while (true)
            { 
                byte[] bytes = ReadChunk(method, _module);

                var disasm = new Disasm();
                var buff = new UnmanagedBuffer(bytes);

                disasm.EIP = new IntPtr(buff.Ptr.ToInt32());

                var instruction = BeaEngine.Disasm(disasm);
                _readOffset -= 8 - instruction; // revert offset back for each byte that was not a part of this instruction
                var mnemonic = disasm.Instruction.Mnemonic.Trim();

                if (mnemonic == "ret") //TODO: Check if this is the only return in function, e.g. check for jumps that go beyond this address
                {
                    Marshal.FreeHGlobal(buff.Ptr);
                    break;
                }

                rawInstructions.Add(Clone(disasm));
                //disasm.EIP = new IntPtr(disasm.EIP.ToInt32() + instruction);

                Marshal.FreeHGlobal(buff.Ptr);
            }

            //while(rawInstructions.First().Instruction.Mnemonic.Trim() == "pop")
            //    rawInstructions.Remove(rawInstructions.First());

            while (rawInstructions.Last().Instruction.Mnemonic.Trim() == "pop")
                rawInstructions.Remove(rawInstructions.Last());


            foreach (var instr in rawInstructions)
            {
                switch (instr.Instruction.Mnemonic.Trim())
                {
                    case "mov":
                        Instructions.Add(new X86MOV(instr));
                        break;
                    case "add":
                        Instructions.Add(new X86ADD(instr));
                        break;
                    case "sub":
                        Instructions.Add(new X86SUB(instr));
                        break;
                    case "imul":
                        Instructions.Add(new X86IMUL(instr));
                        break;
                    case "div":
                        Instructions.Add(new X86DIV(instr));
                        break;
                    case "neg":
                        Instructions.Add(new X86NEG(instr));
                        break;
                    case "not":
                        Instructions.Add(new X86NOT(instr));
                        break;
                    case "xor":
                        Instructions.Add(new X86XOR(instr));
                        break;
                    case "pop":
                        Instructions.Add(new X86POP(instr));
                        break;
                }
            }
        }

        private int _readOffset;
        public byte[] ReadChunk(MethodDef method, ModuleDefMD module)
        {
            var stream = module.MetaData.PEImage.CreateFullStream();
            var offset = module.MetaData.PEImage.ToFileOffset(method.RVA);

            byte[] buffer = new byte[8];

            if (_readOffset == 0) //TODO: Don't use hardcoded offset
                _readOffset = (int) offset + 20; // skip to actual calculation code

            stream.Position = _readOffset;

            stream.Read(buffer, 0, 8); // read 8 bytes to make sure that's a whole instruction
            _readOffset += 8;

            return buffer;
        }

        public int Execute(params int[] @params)
        {
            foreach (var param in @params)
                LocalStack.Push(param);

            foreach (var instr in Instructions)
                instr.Execute(Registers, LocalStack);

            return Registers["EAX"];
        }

        public static Disasm Clone(Disasm disasm)
        {
            return new Disasm
            {
                Archi = disasm.Archi,
                Argument1 = disasm.Argument1,
                Argument2 = disasm.Argument2,
                Argument3 = disasm.Argument3,
                CompleteInstr = disasm.CompleteInstr,
                EIP = disasm.EIP,
                Instruction = disasm.Instruction,
                Options = disasm.Options,
                Prefix = disasm.Prefix,
                SecurityBlock = disasm.SecurityBlock,
                VirtualAddr = disasm.VirtualAddr
            };
        }
    }
}
