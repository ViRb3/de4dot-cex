using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using de4dot.blocks;
using de4dot.blocks.cflow;
using de4dot.code.deobfuscators.ConfuserEx.x86;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using FieldAttributes = dnlib.DotNet.FieldAttributes;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using OpCodes = dnlib.DotNet.Emit.OpCodes;
using TypeAttributes = dnlib.DotNet.TypeAttributes;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class ConstantDecrypterBase
    {
        private readonly InstructionEmulator _instructionEmulator = new InstructionEmulator();
        private X86Method _nativeMethod;

        public MethodDef Method { get; set; }
        public byte[] Decrypted { get; set; }
        public uint Magic1 { get; set; }
        public uint Magic2 { get; set; }
        public bool CanRemove { get; set; } = true;

        // native mode
        public MethodDef NativeMethod { get; internal set; }

        // normal mode
        public uint Num1 { get; internal set; }
        public uint Num2 { get; internal set; }

        private int? CalculateKey()
        {
            var popValue = _instructionEmulator.Peek();

            if (popValue == null || !popValue.IsInt32() || !(popValue as Int32Value).AllBitsValid())
                return null;

            _instructionEmulator.Pop();
            var result = _nativeMethod.Execute(((Int32Value) popValue).Value);
            return result;
        }

        private uint CalculateMagic(uint index)
        {
            uint uint_0;
            if (NativeMethod != null)
            {
                _instructionEmulator.Push(new Int32Value((int)index));
                _nativeMethod = new X86Method(NativeMethod, Method.Module as ModuleDefMD); //TODO: Possible null
                var key = CalculateKey();

                uint_0 = (uint)key.Value;
            }
            else
            {
                uint_0 = index * Num1 ^ Num2;
            }

            uint_0 &= 0x3fffffff;
            uint_0 <<= 2;
            return uint_0;
        }

        public string DecryptString(uint index)
        {
            index = CalculateMagic(index);
            var count = BitConverter.ToInt32(Decrypted, (int) index);
            return string.Intern(Encoding.UTF8.GetString(Decrypted, (int) index + 4, count));
        }

        public T DecryptConstant<T>(uint index)
        {
            index = CalculateMagic(index);
            var array = new T[1];
            Buffer.BlockCopy(Decrypted, (int) index, array, 0, Marshal.SizeOf(typeof(T)));
            return array[0];
        }

        public byte[] DecryptArray(uint index)
        {
            index = CalculateMagic(index);
            var count = BitConverter.ToInt32(Decrypted, (int) index);
            //int lengt = BitConverter.ToInt32(Decrypted, (int)index+4);  we actualy dont need that
            var buffer = new byte[count - 4];
            Buffer.BlockCopy(Decrypted, (int) index + 8, buffer, 0, count - 4);
            return buffer;
        }
    }

    public class ConstantsDecrypter
    {
        private readonly ISimpleDeobfuscator _deobfuscator;
        private readonly MethodDef _lzmaMethod;

        private readonly ModuleDef _module;

        private readonly string[] _strDecryptCalledMethods =
        {
            "System.Text.Encoding System.Text.Encoding::get_UTF8()",
            "System.String System.Text.Encoding::GetString(System.Byte[],System.Int32,System.Int32)",
            "System.Array System.Array::CreateInstance(System.Type,System.Int32)",
            "System.String System.String::Intern(System.String)",
            "System.Void System.Buffer::BlockCopy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)",
            "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)",
            "System.Type System.Type::GetElementType()"
        };

        private byte[] _decryptedBytes;
        private FieldDef _decryptedField, _arrayField;
        internal TypeDef ArrayType;

        public ConstantsDecrypter(ModuleDef module, MethodDef lzmaMethod, ISimpleDeobfuscator deobfsucator)
        {
            _module = module;
            _lzmaMethod = lzmaMethod;
            _deobfuscator = deobfsucator;
        }

        public bool CanRemoveLzma { get; private set; }

        public TypeDef Type => ArrayType;

        public MethodDef Method { get; private set; }

        public List<FieldDef> Fields => new List<FieldDef> {_decryptedField, _arrayField};

        public List<ConstantDecrypterBase> Decrypters { get; } = new List<ConstantDecrypterBase>();

        public bool Detected => Method != null && _decryptedBytes != null && Decrypters.Count != 0 &&
                                _decryptedField != null && _arrayField != null;

        public void Find()
        {
            var moduleCctor = DotNetUtils.GetModuleTypeCctor(_module);
            if (moduleCctor == null)
                return;
            foreach (var inst in moduleCctor.Body.Instructions)
            {
                if (inst.OpCode != OpCodes.Call)
                    continue;
                if (!(inst.Operand is MethodDef))
                    continue;
                var method = (MethodDef) inst.Operand;
                if (!method.HasBody || !method.IsStatic)
                    continue;
                if (!DotNetUtils.IsMethod(method, "System.Void", "()"))
                    continue;

                _deobfuscator.Deobfuscate(method, SimpleDeobfuscatorFlags.Force);

                if (!IsStringDecrypterInit(method, out FieldDef aField, out FieldDef dField))
                    continue;
                try
                {
                    _decryptedBytes = DecryptArray(method, aField.InitialValue);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    return;
                }

                _arrayField = aField;
                _decryptedField = dField;
                ArrayType = DotNetUtils.GetType(_module, _arrayField.FieldSig.Type);
                Method = method;
                Decrypters.AddRange(FindStringDecrypters(moduleCctor.DeclaringType));
                CanRemoveLzma = true;
            }
        }

        private bool IsStringDecrypterInit(MethodDef method, out FieldDef aField, out FieldDef dField)
        {
            aField = null;
            dField = null;
            var instructions = method.Body.Instructions;
            if (instructions.Count < 15)
                return false;

            if (!instructions[0].IsLdcI4())
                return false;
            if (!instructions[1].IsStloc()) //uint num = 96u;
                return false;

            if (!instructions[2].IsLdcI4())
                return false;
            if (instructions[0].GetLdcI4Value() != instructions[2].GetLdcI4Value())
                return false;
            if (instructions[3].OpCode != OpCodes.Newarr)
                return false;
            if (instructions[3].Operand.ToString() != "System.UInt32")
                return false;
            if (instructions[4].OpCode != OpCodes.Dup)
                return false;
            if (instructions[5].OpCode != OpCodes.Ldtoken)
                return false;
            aField = instructions[5].Operand as FieldDef;
            if (aField?.InitialValue == null)
                return false;
            if (aField.Attributes != (FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA))
                return false;
            if (instructions[6].OpCode != OpCodes.Call)
                return false;
            if (instructions[6].Operand.ToString() !=
                "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)"
            )
                return false;
            if (!instructions[7].IsStloc()) // uint[] array = new uint[] {.....};
                return false;

            var l = instructions.Count;
            if (!instructions[l - 4].IsLdloc())
                return false;
            if (instructions[l - 3].OpCode != OpCodes.Call)
                return false;
            if (instructions[l - 3].Operand != _lzmaMethod)
                return false;
            if (instructions[l - 2].OpCode != OpCodes.Stsfld) //<Module>.byte_0 = <Module>.smethod_0(array4);
                return false;
            dField = instructions[l - 2].Operand as FieldDef;
            if (dField == null)
                return false;

            return true;
        }

        private byte[] DecryptArray(MethodDef method, byte[] encryptedArray)
        {
            ModuleDefUser tempModule = new ModuleDefUser("TempModule");
            
            AssemblyDef tempAssembly = new AssemblyDefUser("TempAssembly");
            tempAssembly.Modules.Add(tempModule);
            
            var tempType = new TypeDefUser("", "TempType", tempModule.CorLibTypes.Object.TypeDefOrRef);
            tempType.Attributes = TypeAttributes.Public | TypeAttributes.Class;
            MethodDef tempMethod = Utils.Clone(method);

            tempMethod.ReturnType = new SZArraySig(tempModule.CorLibTypes.Byte);
            tempMethod.MethodSig.Params.Add(new SZArraySig(tempModule.CorLibTypes.Byte));
            tempMethod.Attributes = MethodAttributes.Public | MethodAttributes.Static;

            for (int i = 0; i < 5; i++)
                tempMethod.Body.Instructions.RemoveAt(2); // read encrypted array from argument
            tempMethod.Body.Instructions.Insert(2, OpCodes.Ldarg_0.ToInstruction());

            for (int i = 0; i < 2; i++)
                tempMethod.Body.Instructions.RemoveAt(tempMethod.Body.Instructions.Count -
                                                      2); // make return decrypted array

            tempType.Methods.Add(tempMethod);
            tempModule.Types.Add(tempType);
            
            using (MemoryStream memoryStream = new MemoryStream())
            {
                ModuleWriterOptions moduleWriterOptions = new ModuleWriterOptions();
                moduleWriterOptions.MetaDataOptions = new MetaDataOptions();

                tempModule.Write(memoryStream, moduleWriterOptions);

                Assembly patchedAssembly = Assembly.Load(memoryStream.ToArray());
                var type = patchedAssembly.ManifestModule.GetType("TempType");
                var methods = type.GetMethods();
                MethodInfo patchedMethod = methods.First(m => m.IsPublic && m.IsStatic);
                byte[] decryptedBytes = (byte[]) patchedMethod.Invoke(null, new object[]{encryptedArray});
                return Lzma.Decompress(decryptedBytes);
            }
        }

        private IEnumerable<ConstantDecrypterBase> FindStringDecrypters(TypeDef type)
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody)
                    continue;
                if (!method.Signature.ContainsGenericParameter)
                    continue;
                var sig = method.MethodSig;
                if (sig?.Params.Count != 1)
                    continue;
                if (sig.Params[0].GetElementType() != ElementType.U4)
                    continue;
                if (!(sig.RetType.RemovePinnedAndModifiers() is GenericMVar))
                    continue;
                if (sig.GenParamCount != 1)
                    continue;

                _deobfuscator.Deobfuscate(method, SimpleDeobfuscatorFlags.Force);

                if (IsNativeStringDecrypter(method, out MethodDef nativeMethod))
                {
                    yield return new ConstantDecrypterBase
                    {
                        Decrypted = _decryptedBytes,
                        Method = method,
                        NativeMethod = nativeMethod
                    };
                }
                if (IsNormalStringDecrypter(method, out int num1, out int num2))
                {
                    yield return new ConstantDecrypterBase
                    {
                        Decrypted = _decryptedBytes,
                        Method = method,
                        Num1 = (uint)num1,
                        Num2 = (uint)num2
                    };
                }
            }
        }

        private bool IsNormalStringDecrypter(MethodDef method, out int num1, out int num2)
        {
            num1 = 0;
            num2 = 0;
            var instr = method.Body.Instructions;
            if (instr.Count < 25)
                return false;

            var i = 0;

            if (!instr[i++].IsLdarg())
                return false;
            if (!instr[i].IsLdcI4())
                return false;
            num1 = (int)instr[i++].Operand;
            if (instr[i++].OpCode != OpCodes.Mul)
                return false;
            if (!instr[i].IsLdcI4())
                return false;
            num2 = (int)instr[i++].Operand;
            if (instr[i++].OpCode != OpCodes.Xor)
                return false;

            if (!instr[i++].IsStarg()) //uint_0 = (uint_0 * 2857448701u ^ 1196001109u);
                return false;

            if (!instr[i++].IsLdarg())
                return false;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 0x1E)
                return false;
            if (instr[i++].OpCode != OpCodes.Shr_Un)
                return false;
            if (!instr[i++].IsStloc()) //uint num = uint_0 >> 30;
                return false;
            i++;
            //TODO: Implement
            //if (!instr[10].IsLdloca())
            //    return;
            if (instr[i++].OpCode != OpCodes.Initobj)
                return false;
            if (!instr[i++].IsLdarg())
                return false;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 0x3FFFFFFF)
                return false;
            if (instr[i++].OpCode != OpCodes.And)
                return false;
            if (!instr[i++].IsStarg()) //uint_0 &= 1073741823u;
                return false;

            if (!instr[i++].IsLdarg())
                return false;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 2)
                return false;
            if (instr[i++].OpCode != OpCodes.Shl)
                return false;
            if (!instr[i++].IsStarg()) //uint_0 <<= 2;
                return false;

            foreach (var mtd in _strDecryptCalledMethods)
                if (!DotNetUtils.CallsMethod(method, mtd))
                    return false;
            //TODO: Implement
            //if (!DotNetUtils.LoadsField(method, decryptedField))
            //    return;
            return true;
        }

        private bool IsNativeStringDecrypter(MethodDef method, out MethodDef nativeMethod)
        {
            nativeMethod = null;
            var instr = method.Body.Instructions;
            if (instr.Count < 25)
                return false;

            var i = 0;

            if (!instr[i++].IsLdarg())
                return false;

            if (instr[i].OpCode != OpCodes.Call)
                return false;

            nativeMethod = instr[i++].Operand as MethodDef;

            if (nativeMethod == null || !nativeMethod.IsStatic || !nativeMethod.IsNative)
                return false;
            if (!DotNetUtils.IsMethod(nativeMethod, "System.Int32", "(System.Int32)"))
                return false;

            if (!instr[i++].IsStarg()) //uint_0 = (uint_0 * 2857448701u ^ 1196001109u);
                return false;

            if (!instr[i++].IsLdarg())
                return false;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 0x1E)
                return false;
            if (instr[i++].OpCode != OpCodes.Shr_Un)
                return false;
            if (!instr[i++].IsStloc()) //uint num = uint_0 >> 30;
                return false;
            i++;
            //TODO: Implement
            //if (!instr[10].IsLdloca())
            //    return;
            if (instr[i++].OpCode != OpCodes.Initobj)
                return false;
            if (!instr[i++].IsLdarg())
                return false;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 0x3FFFFFFF)
                return false;
            if (instr[i++].OpCode != OpCodes.And)
                return false;
            if (!instr[i++].IsStarg()) //uint_0 &= 1073741823u;
                return false;

            if (!instr[i++].IsLdarg())
                return false;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 2)
                return false;
            if (instr[i++].OpCode != OpCodes.Shl)
                return false;
            if (!instr[i++].IsStarg()) //uint_0 <<= 2;
                return false;

            foreach (var mtd in _strDecryptCalledMethods)
                if (!DotNetUtils.CallsMethod(method, mtd))
                    return false;
            //TODO: Implement
            //if (!DotNetUtils.LoadsField(method, decryptedField))
            //    return;
            return true;
        }

        private static bool VerifyGenericArg(MethodSpec gim, ElementType etype)
        {
            var gims = gim?.GenericInstMethodSig;
            if (gims == null || gims.GenericArguments.Count != 1)
                return false;
            return gims.GenericArguments[0].GetElementType() == etype;
        }

        public string DecryptString(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.String))
                return null;
            return info.DecryptString(magic1);
        }

        public object DecryptSByte(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.I1))
                return null;
            return info.DecryptConstant<sbyte>(magic1);
        }

        public object DecryptByte(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.U1))
                return null;
            return info.DecryptConstant<byte>(magic1);
        }

        public object DecryptInt16(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.I2))
                return null;
            return info.DecryptConstant<short>(magic1);
        }

        public object DecryptUInt16(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.U2))
                return null;
            return info.DecryptConstant<ushort>(magic1);
        }

        public object DecryptInt32(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.I4))
                return null;
            return info.DecryptConstant<int>(magic1);
        }

        public object DecryptUInt32(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.U4))
                return null;
            return info.DecryptConstant<uint>(magic1);
        }

        public object DecryptInt64(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.I8))
                return null;
            return info.DecryptConstant<long>(magic1);
        }

        public object DecryptUInt64(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.U8))
                return null;
            return info.DecryptConstant<ulong>(magic1);
        }

        public object DecryptSingle(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.R4))
                return null;
            return info.DecryptConstant<float>(magic1);
        }

        public object DecryptDouble(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.R8))
                return null;
            return info.DecryptConstant<double>(magic1);
        }

        public object DecryptArray(ConstantDecrypterBase info, MethodSpec gim, uint magic1)
        {
            if (!VerifyGenericArg(gim, ElementType.SZArray))
                return null;
            return info.DecryptArray(magic1);
        }
    }
}