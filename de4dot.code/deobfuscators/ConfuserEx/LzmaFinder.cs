using System.Collections.Generic;
using System.Linq;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class LzmaFinder
    {
        private readonly ISimpleDeobfuscator _deobfuscator;

        private readonly ModuleDef _module;

        public LzmaFinder(ModuleDef module, ISimpleDeobfuscator deobfuscator)
        {
            this._module = module;
            this._deobfuscator = deobfuscator;
        }

        public MethodDef Method { get; private set; }

        public List<TypeDef> Types { get; } = new List<TypeDef>();

        public bool FoundLzma => Method != null && Types.Count != 0;

        public void Find()
        {
            var moduleType = DotNetUtils.GetModuleType(_module);
            if (moduleType == null)
                return;
            foreach (var method in moduleType.Methods)
            {
                if (!method.HasBody || !method.IsStatic)
                    continue;
                if (!DotNetUtils.IsMethod(method, "System.Byte[]", "(System.Byte[])"))
                    continue;
                _deobfuscator.Deobfuscate(method, SimpleDeobfuscatorFlags.Force);
                if (!IsLzmaMethod(method))
                    continue;
                Method = method;
                var type = ((MethodDef) method.Body.Instructions[3].Operand).DeclaringType;
                ExtractNestedTypes(type);
            }
        }

        private bool IsLzmaMethod(MethodDef method)
        {
            var instructions = method.Body.Instructions;

            if (instructions.Count < 60)
                return false;

            var firstInstruction = instructions.FirstOrDefault(
                instr =>
                    instr.OpCode == OpCodes.Newobj &&
                    instr.Operand.ToString() == "System.Void System.IO.MemoryStream::.ctor(System.Byte[])");

            if (firstInstruction == null)
                return false;

            var i = instructions.IndexOf(firstInstruction) + 1;

            if (!instructions[i++].IsStloc())
                return false;
            if (instructions[i++].OpCode != OpCodes.Newobj)
                return false;
            if (!instructions[i++].IsStloc()) //<Module>.Class1 @class = new <Module>.Class1();
                return false;

            if (!instructions[i].IsLdcI4() || instructions[i++].GetLdcI4Value() != 5)
                return false;
            if (instructions[i++].OpCode != OpCodes.Newarr)
                return false;
            if (!instructions[i++].IsStloc()) //byte[] buffer = new byte[5];
                return false;

            if (!instructions[i++].IsLdloc())
                return false;
            if (!instructions[i++].IsLdloc())
                return false;
            if (!instructions[i].IsLdcI4() || instructions[i++].GetLdcI4Value() != 0)
                return false;
            if (!instructions[i].IsLdcI4() || instructions[i++].GetLdcI4Value() != 5)
                return false;
            if (instructions[i].OpCode != OpCodes.Callvirt || instructions[i++].Operand.ToString() !=
                "System.Int32 System.IO.Stream::Read(System.Byte[],System.Int32,System.Int32)")
                return false;
            if (instructions[i++].OpCode != OpCodes.Pop) //memoryStream.Read(buffer, 0, 5);
                return false;

            if (!instructions[i++].IsLdloc())
                return false;
            if (!instructions[i++].IsLdloc())
                return false;
            if (instructions[i++].OpCode != OpCodes.Callvirt) //@class.method_5(buffer);
                return false;

            firstInstruction =
                instructions.FirstOrDefault(
                    instr =>
                        instr.OpCode == OpCodes.Callvirt &&
                        instr.Operand.ToString() == "System.Int32 System.IO.Stream::ReadByte()");

            if (firstInstruction == null)
                return false;
            if (i >= instructions.IndexOf(firstInstruction))
                return false;

            i = instructions.IndexOf(firstInstruction) + 1;

            if (!instructions[i++].IsStloc()) //int num2 = memoryStream.ReadByte();
                return false;

            if (!instructions[i++].IsLdloc())
                return false;
            if (!instructions[i++].IsLdloc())
                return false;
            if (instructions[i++].OpCode != OpCodes.Conv_U1)
                return false;
            if (instructions[i++].OpCode != OpCodes.Conv_U8)
                return false;
            if (!instructions[i].IsLdcI4() || instructions[i++].GetLdcI4Value() != 8)
                return false;
            if (!instructions[i++].IsLdloc())
                return false;
            if (instructions[i++].OpCode != OpCodes.Mul)
                return false;
            if (!instructions[i].IsLdcI4() || instructions[i++].GetLdcI4Value() != 0x3F)
                return false;
            if (instructions[i++].OpCode != OpCodes.And)
                return false;
            if (instructions[i++].OpCode != OpCodes.Shl)
                return false;
            if (instructions[i++].OpCode != OpCodes.Or)
                return false;
            if (!instructions[i++].IsStloc()) //num |= (long)((long)((ulong)((byte)num2)) << 8 * i);
                return false;

            firstInstruction =
                instructions.FirstOrDefault(
                    instr =>
                        instr.OpCode == OpCodes.Newobj &&
                        instr.Operand.ToString() ==
                        "System.Void System.IO.MemoryStream::.ctor(System.Byte[],System.Boolean)");

            if (firstInstruction == null)
                return false;
            if (i >= instructions.IndexOf(firstInstruction))
                return false;

            i = instructions.IndexOf(firstInstruction) + 1;

            if (!instructions[i++].IsStloc()) //MemoryStream stream_ = new MemoryStream(array, true);
                return false;

            if (!instructions[i++].IsLdloc())
                return false;
            if (instructions[i].OpCode != OpCodes.Callvirt || instructions[i++].Operand.ToString() !=
                "System.Int64 System.IO.Stream::get_Length()")
                return false;
            if (instructions[i].OpCode != OpCodes.Ldc_I8 || (long) instructions[i++].Operand != 13L)
                return false;
            if (instructions[i++].OpCode != OpCodes.Sub)
                return false;
            if (!instructions[i++].IsStloc()) //long long_ = memoryStream.Length - 13L;
                return false;

            return true;
        }

        private void ExtractNestedTypes(TypeDef type)
        {
            foreach (var method in type.Methods)
                if (method.HasBody)
                {
                    var instr = method.Body.Instructions;
                    foreach (var inst in instr)
                        if (inst.Operand is MethodDef)
                        {
                            var ntype = (inst.Operand as MethodDef).DeclaringType;
                            if (!ntype.IsNested)
                                continue;
                            if (Types.Contains(ntype))
                                continue;
                            Types.Add(ntype);
                            ExtractNestedTypes(ntype);
                        }
                }
        }
    }
}