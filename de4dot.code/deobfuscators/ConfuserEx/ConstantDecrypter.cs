using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using de4dot.blocks.cflow;
using de4dot.code.deobfuscators.ConfuserEx.x86;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class ConstantDecrypterBase
    {
        private X86Method _nativeMethod;
        private readonly InstructionEmulator _instructionEmulator = new InstructionEmulator();

        private int? CalculateKey()
        {
            var popValue = _instructionEmulator.Peek();

            if (popValue == null || !popValue.IsInt32() || !(popValue as Int32Value).AllBitsValid())
                return null;

            _instructionEmulator.Pop();
            int result = _nativeMethod.Execute(((Int32Value)popValue).Value);
            return result;
        }

        public MethodDef Method { get; set; }
        public MethodDef NativeMethod { get; set; }
        public byte[] Decrypted { get; set; }
        public uint Magic1 { get; set; }
        public uint Magic2 { get; set; }
        public bool CanRemove { get; set; } = true;

        private uint CalculateMagic(uint index)
        {
            _instructionEmulator.Push(new Int32Value((int)index));
            _nativeMethod = new X86Method(NativeMethod, Method.Module as ModuleDefMD); //TODO: Possible null
            int? key = CalculateKey();

            uint uint_0 = (uint) key.Value;
            uint_0 &= 0x3fffffff;
            uint_0 <<= 2;
            return uint_0;
        }
        public string DecryptString(uint index)
        {
            index = CalculateMagic(index);
            int count = BitConverter.ToInt32(Decrypted, (int)index);
            return string.Intern(Encoding.UTF8.GetString(Decrypted, (int)index + 4, count));
        }
        public T DecryptConstant<T>(uint index)
        {
            index = CalculateMagic(index);
            T[] array = new T[1];
            Buffer.BlockCopy(Decrypted, (int)index, array, 0, Marshal.SizeOf(typeof(T)));
            return array[0];
        }
        public byte[] DecryptArray(uint index)
        {
            index = CalculateMagic(index);
            int count = BitConverter.ToInt32(Decrypted, (int)index);
            //int lengt = BitConverter.ToInt32(Decrypted, (int)index+4);  we actualy dont need that
            byte[] buffer = new byte[count - 4];
            Buffer.BlockCopy(Decrypted, (int)index + 8, buffer, 0, count - 4);
            return buffer;
        }
    }

    public class ConstantsDecrypter
    {
        TypeDef arrayType;
        MethodDef constantsDecInitMethod;
        FieldDef decryptedField, arrayField;
        List<ConstantDecrypterBase> constantDecrpers = new List<ConstantDecrypterBase>();
        byte[] decryptedBytes;
        bool canRemoveLzma = true;

        public bool CanRemoveLzma
        {
            get { return canRemoveLzma; }
        }
        public TypeDef Type
        {
            get { return arrayType; }
        }
        public MethodDef Method
        {
            get { return constantsDecInitMethod; }
        }
        public List<FieldDef> Fields
        {
            get { return new List<FieldDef>() { decryptedField, arrayField }; }
        }
        public List<ConstantDecrypterBase> Decrypters
        {
            get { return constantDecrpers; }
        }
        public bool Detected
        {
            get { return constantsDecInitMethod != null && decryptedBytes != null && constantDecrpers.Count != 0 && decryptedField != null && arrayField != null; }
        }

        ModuleDef module;
        MethodDef lzmaMethod;
        ISimpleDeobfuscator deobfuscator;
        public ConstantsDecrypter(ModuleDef module, MethodDef lzmaMethod, ISimpleDeobfuscator deobfsucator)
        {
            this.module = module;
            this.lzmaMethod = lzmaMethod;
            this.deobfuscator = deobfsucator;
        }

        public void Find()
        {
            var moduleCctor = DotNetUtils.GetModuleTypeCctor(module);
            if (moduleCctor == null)
                return;
            foreach (var inst in moduleCctor.Body.Instructions)
            {
                if (inst.OpCode != OpCodes.Call)
                    continue;
                if (!(inst.Operand is MethodDef))
                    continue;
                var method = inst.Operand as MethodDef;
                if (!method.HasBody || !method.IsStatic)
                    continue;
                if (!DotNetUtils.IsMethod(method, "System.Void", "()"))
                    continue;
                deobfuscator.Deobfuscate(method, SimpleDeobfuscatorFlags.Force);
                if (!isStrDecryptInit(method))
                    continue;
                constantsDecInitMethod = method;
                FindStringDecrypters(moduleCctor.DeclaringType);
            }
        }

        bool isStrDecryptInit(MethodDef method)
        {
            var instructions = method.Body.Instructions;

            if (instructions.Count < 15)
                return false;

            if (!instructions[0].IsLdcI4())
                return false;
            if (!instructions[1].IsStloc())  //uint num = 96u;
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
            var aField = instructions[5].Operand as FieldDef;
            if (aField == null)
                return false;
            if (aField.InitialValue == null)
                return false;
            if (aField.Attributes != (FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA))
                return false;
            if (instructions[6].OpCode != OpCodes.Call)
                return false;
            if (instructions[6].Operand.ToString() != "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)")
                return false;
            if (!instructions[7].IsStloc())  // uint[] array = new uint[] {.....};
                return false;

            var l = instructions.Count;
            if (!instructions[l - 4].IsLdloc())
                return false;
            if (instructions[l - 3].OpCode != OpCodes.Call)
                return false;
            if (instructions[l - 3].Operand != lzmaMethod)
                return false;
            if (instructions[l - 2].OpCode != OpCodes.Stsfld)  //<Module>.byte_0 = <Module>.smethod_0(array4);
                return false;
            var dField = instructions[l - 2].Operand as FieldDef;
            if (dField == null)
                return false;
            try
            {
                DecryptArray(ConvertArray<uint, byte>(aField.InitialValue));
            }
            catch (Exception e) { Console.WriteLine(e.Message); canRemoveLzma = false; return false; }
            arrayField = aField;
            arrayType = DotNetUtils.GetType(module, aField.FieldSig.Type);
            decryptedField = dField;
            return true;
        }

        private T[] ConvertArray<T, T1>(T1[] array)
        {
            int l = Marshal.SizeOf(typeof(T));
            int l1 = Marshal.SizeOf(typeof(T1));
            var buffer = new T[(array.Length * l1) / l];
            Buffer.BlockCopy(array, 0, buffer, 0, array.Length * l1);
            return buffer;
        }

        private void DecryptArray(uint[] array)
        {
            uint num = 1680u; // array size?
            uint[] array2 = new uint[16];
            uint num2 = 3186233426u;
            for (int i = 0; i < 16; i++)
            {
                num2 ^= num2 >> 12;
                num2 ^= num2 << 25;
                num2 ^= num2 >> 27;
                array2[i] = num2;
            }
            int num3 = 0;
            int num4 = 0;
            uint[] array3 = new uint[16];
            byte[] array4 = new byte[num * 4u];
            while ((long)num3 < (long)((ulong)num))
            {
                for (int j = 0; j < 16; j++)
                {
                    array3[j] = array[num3 + j];
                }
                uint num5 = array3[9] >> 23;
                array3[0] = array3[0] * 865957733u;
                array3[9] = array3[9] << 9;
                array3[9] = (array3[9] | num5);
                array3[3] = (array3[3] ^ 4272581837u);
                array3[8] = (array3[8] ^ array2[8]);
                num5 = (array3[14] & 3955221806u);
                num5 *= 1105615415u;
                array3[14] = (array3[14] & 339745489u);
                array3[14] = (array3[14] | (array3[0] & 3955221806u));
                array3[15] = (array3[15] ^ array3[8]);
                array3[0] = (array3[0] & 339745489u);
                array3[0] = (array3[0] | num5 * 809663367u);
                array3[14] = (array3[14] ^ 1753824488u);
                num5 = array3[11] << 18;
                array3[11] = array3[11] >> 14;
                array3[1] = array3[1] - 301755752u;
                array3[11] = (array3[11] | num5);
                uint num6 = array3[14] << 3;
                num5 = (array3[9] & 2370496838u);
                array3[10] = array3[10] - 4147007853u;
                uint num7 = array3[14] << 4;
                num5 *= 2575732745u;
                num6 += array3[14] << 4;
                array3[9] = (array3[9] & 1924470457u);
                array3[9] = (array3[9] | (array3[2] & 2370496838u));
                array3[12] = array3[12] - array3[6];
                array3[2] = (array3[2] & 1924470457u);
                array3[0] = array3[0] - array3[4];
                array3[2] = (array3[2] | num5 * 593100345u);
                num5 = array3[6] * 993944645u;
                array3[6] = array3[5];
                uint num8 = array3[14] * 19u;
                array3[5] = num5 * 679153293u;
                num5 = (array3[1] & 4141471236u);
                num8 += array3[5] * 67u;
                num8 += array3[10] * 43u;
                array3[13] = (array3[13] ^ array2[13]);
                array3[1] = (array3[1] & 153496059u);
                num6 += array3[5] * 92u;
                num7 += array3[5] * 57u;
                num7 += array3[10] * 37u;
                num5 *= 831032307u;
                array3[1] = (array3[1] | (array3[12] & 4141471236u));
                array3[0] = (array3[0] ^ array2[0]);
                array3[12] = (array3[12] & 153496059u);
                array3[11] = (array3[11] ^ array2[11]);
                num6 += array3[10] << 6;
                array3[12] = (array3[12] | num5 * 419693883u);
                num7 += array3[15] * 107u;
                array3[3] = (array3[3] ^ array2[3]);
                num5 = (array3[13] & 2032982899u);
                array3[13] = (array3[13] & 2261984396u);
                num5 *= 3754449215u;
                num8 += array3[15] * 125u;
                num6 += array3[15] * 179u;
                array3[13] = (array3[13] | (array3[7] & 2032982899u));
                array3[7] = (array3[7] & 2261984396u);
                array3[7] = (array3[7] | num5 * 1302730431u);
                num5 = array3[14] * 7u;
                num5 += array3[5] * 25u;
                array3[12] = (array3[12] ^ ~array3[4]);
                num5 += array3[10] << 4;
                array3[5] = num6;
                array3[10] = num7;
                num6 = array3[2] >> 19;
                num7 = array3[11] >> 19;
                num5 += array3[15] * 46u;
                array3[15] = num8;
                num8 = array3[0] << 2;
                array3[2] = array3[2] << 13;
                array3[11] = array3[11] << 13;
                array3[14] = num5;
                array3[0] = array3[0] >> 30;
                array3[2] = (array3[2] | num6);
                array3[6] = (array3[6] ^ 825592879u);
                array3[2] = (array3[2] ^ array2[2]);
                array3[11] = (array3[11] | num7);
                num5 = array3[15] << 1;
                array3[0] = (array3[0] | num8);
                num8 = array3[15] * 23u;
                num7 = array3[15] * 7u;
                num8 += array3[7] * 45u;
                num7 += array3[7] * 11u;
                num5 += array3[15];
                array3[9] = (array3[9] ^ array2[9]);
                num5 += array3[7] * 7u;
                num8 += array3[13] << 7;
                array3[3] = (array3[3] ^ ~array3[8]);
                array3[10] = array3[10] * 2256145475u;
                num6 = array3[15] << 2;
                num6 += array3[15];
                num7 += array3[13] << 5;
                num7 += array3[1] << 1;
                num6 += array3[7] << 2;
                num6 += array3[7] << 3;
                num8 += array3[13];
                num8 += array3[1] * 143u;
                num5 += array3[13] << 2;
                num6 += array3[13] << 1;
                num7 += array3[1] << 5;
                num5 += array3[13] << 4;
                array3[15] = num7;
                num5 += array3[1] * 23u;
                num6 += array3[13] << 5;
                array3[7] = num5;
                num6 += array3[1] * 39u;
                array3[1] = num8;
                num8 = array3[1] * 26u;
                num7 = array3[1] << 6;
                array3[7] = (array3[7] ^ array2[7]);
                array3[13] = num6;
                num5 = array3[1] << 1;
                num5 += array3[1] << 3;
                num6 = array3[1] * 13u;
                num5 += array3[13] << 1;
                num7 += array3[1];
                num6 += array3[13] * 45u;
                array3[9] = (array3[9] ^ 786150263u);
                num8 += array3[13] * 88u;
                num6 += array3[2] * 67u;
                array3[8] = (array3[8] ^ 110539985u);
                num5 += array3[13] << 5;
                num6 += array3[11] << 1;
                num8 += array3[2] * 133u;
                array3[10] = (array3[10] ^ array2[10]);
                num8 += array3[11] << 6;
                array3[15] = array3[15] - 2992485470u;
                array3[0] = array3[0] - array3[6];
                num6 += array3[11] << 5;
                num5 += array3[2] * 51u;
                num5 += array3[11] * 25u;
                array3[12] = (array3[12] ^ ~array3[3]);
                num7 += array3[13] * 222u;
                array3[13] = num5;
                array3[1] = num6;
                array3[13] = array3[13] * 3578289835u;
                num6 = (array3[10] & 381620437u);
                array3[10] = (array3[10] & 3913346858u);
                num5 = array3[0] * 14u;
                num7 += array3[2] * 333u;
                array3[2] = num8;
                num5 += array3[3] * 11u;
                array3[10] = (array3[10] | (array3[14] & 381620437u));
                array3[7] = (array3[7] ^ ~array3[4]);
                num6 *= 3323466531u;
                array3[14] = (array3[14] & 3913346858u);
                num8 = array3[0] << 2;
                num5 += array3[5] * 54u;
                array3[14] = (array3[14] | num6 * 1991488651u);
                num7 += array3[11] * 164u;
                num6 = (array3[2] & 2341248020u);
                array3[11] = num7;
                num7 = array3[0] * 11u;
                num8 += array3[0] << 4;
                array3[2] = (array3[2] & 1953719275u);
                num8 += array3[3] << 2;
                array3[2] = (array3[2] | (array3[11] & 2341248020u));
                num8 += array3[3] << 4;
                num6 *= 4030567715u;
                array3[14] = (array3[14] ^ array2[14]);
                array3[11] = (array3[11] & 1953719275u);
                array3[11] = (array3[11] | num6 * 62866059u);
                num6 = array3[0] << 2;
                num8 += array3[5] * 90u;
                num7 += array3[3] << 4;
                num7 += array3[5] << 2;
                num6 += array3[0];
                array3[12] = (array3[12] ^ array2[12]);
                num7 += array3[5] << 6;
                num8 += array3[13] * 117u;
                array3[9] = (array3[9] ^ array3[5]);
                num5 += array3[13] * 52u;
                num6 += array3[3] << 1;
                num6 += array3[3];
                num7 += array3[13] * 126u;
                num6 += array3[5] << 4;
                num6 += array3[5];
                array3[5] = num8;
                array3[3] = num5;
                num6 += array3[13] * 11u;
                array3[0] = num6;
                array3[13] = num7;
                num6 = array3[6] << 1;
                num6 += array3[15] << 1;
                num5 = array3[12] << 29;
                num6 += array3[15] << 2;
                num7 = array3[7] << 12;
                array3[11] = array3[11] - array3[10];
                array3[7] = array3[7] >> 20;
                array3[12] = array3[12] >> 3;
                array3[12] = (array3[12] | num5);
                array3[14] = (array3[14] ^ ~array3[8]);
                array3[1] = (array3[1] ^ array2[1]);
                array3[1] = (array3[1] ^ 3215842197u);
                num8 = array3[6] * 7u;
                array3[7] = (array3[7] | num7);
                num8 += array3[15] * 26u;
                num5 = array3[6] << 2;
                num5 += array3[15] << 2;
                array3[9] = array3[9] - array3[2];
                num7 = array3[6] << 2;
                array3[4] = (array3[4] ^ array2[4]);
                num6 += array3[4] << 4;
                array3[3] = (array3[3] ^ 1425746098u);
                num5 += array3[15];
                num8 += array3[4] * 69u;
                num5 += array3[4] * 15u;
                num7 += array3[6];
                num6 += array3[1] * 15u;
                num8 += array3[1] * 63u;
                array3[6] = num6;
                num7 += array3[15] * 11u;
                num7 += array3[4] * 31u;
                num7 += array3[1] * 30u;
                num5 += array3[1] << 4;
                array3[5] = (array3[5] ^ array2[5]);
                array3[4] = num7;
                num7 = (array3[5] & 2375297997u);
                array3[6] = (array3[6] ^ array2[6]);
                num7 *= 3574473459u;
                array3[15] = num5;
                array3[5] = (array3[5] & 1919669298u);
                array3[5] = (array3[5] | (array3[13] & 2375297997u));
                array3[1] = num8;
                array3[15] = (array3[15] ^ array2[15]);
                num8 = array3[0] << 5;
                array3[13] = (array3[13] & 1919669298u);
                array3[13] = (array3[13] | num7 * 2683487803u);
                array3[0] = array3[0] >> 27;
                array3[0] = (array3[0] | num8);
                for (int k = 0; k < 16; k++)
                {
                    uint num9 = array3[k];
                    array4[num4++] = (byte)num9;
                    array4[num4++] = (byte)(num9 >> 8);
                    array4[num4++] = (byte)(num9 >> 16);
                    array4[num4++] = (byte)(num9 >> 24);
                    array2[k] ^= num9;
                }
                num3 += 16;
            }
            decryptedBytes = Lzma.Decompress(array4);
        }

        private void FindStringDecrypters(TypeDef type)
        {
            foreach (var method in type.Methods)
            {
                if (!method.HasBody)
                    continue;
                if (!(method.Signature.ContainsGenericParameter))
                    continue;
                var sig = method.MethodSig;
                if (sig == null)
                    continue;
                if (sig.Params.Count != 1)
                    continue;
                if (sig.Params[0].GetElementType() != ElementType.U4)
                    continue;
                if (!(sig.RetType.RemovePinnedAndModifiers() is GenericMVar))
                    continue;
                if (sig.GenParamCount != 1)
                    continue;
                deobfuscator.Deobfuscate(method, SimpleDeobfuscatorFlags.Force);
                IsStringDecrypter(method);
            }
        }

        string[] strDecryptCalledMethods = {
            "System.Text.Encoding System.Text.Encoding::get_UTF8()",
            "System.String System.Text.Encoding::GetString(System.Byte[],System.Int32,System.Int32)",
            "System.Array System.Array::CreateInstance(System.Type,System.Int32)",
            "System.String System.String::Intern(System.String)",
            "System.Void System.Buffer::BlockCopy(System.Array,System.Int32,System.Array,System.Int32,System.Int32)",
            "System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)",
            "System.Type System.Type::GetElementType()"
        };

        private void IsStringDecrypter(MethodDef method)
        {
            var instr = method.Body.Instructions;
            if (instr.Count < 25)
                return;

            int i = 0;

            if (!instr[i++].IsLdarg())
                return;

            if (instr[i].OpCode != OpCodes.Call)
                return;

            var nativeMethod = instr[i++].Operand as MethodDef;

            if (nativeMethod == null || !nativeMethod.IsStatic || !nativeMethod.IsNative)
                return;
            if (!DotNetUtils.IsMethod(nativeMethod, "System.Int32", "(System.Int32)"))
                return;

            if (!instr[i++].IsStarg())  //uint_0 = (uint_0 * 2857448701u ^ 1196001109u);
                return;

            if (!instr[i++].IsLdarg())
                return;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 0x1E)
                return;
            if (instr[i++].OpCode != OpCodes.Shr_Un)
                return;
            if (!instr[i++].IsStloc()) //uint num = uint_0 >> 30;
                return;
            i++;
            //TODO: Implement
            //if (!instr[10].IsLdloca())
            //    return;
            if (instr[i++].OpCode != OpCodes.Initobj)
                return;
            if (!instr[i++].IsLdarg())
                return;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 0x3FFFFFFF)
                return;
            if (instr[i++].OpCode != OpCodes.And)
                return;
            if (!instr[i++].IsStarg())  //uint_0 &= 1073741823u;
                return;

            if (!instr[i++].IsLdarg())
                return;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 2)
                return;
            if (instr[i++].OpCode != OpCodes.Shl)
                return;
            if (!instr[i++].IsStarg())  //uint_0 <<= 2;
                return;

            foreach (var mtd in strDecryptCalledMethods)
                if (!DotNetUtils.CallsMethod(method, mtd))
                    return;
            //TODO: Implement
            //if (!DotNetUtils.LoadsField(method, decryptedField))
            //    return;
            constantDecrpers.Add(new ConstantDecrypterBase()
            {
                Decrypted = decryptedBytes,
                Method = method,
                NativeMethod = nativeMethod,
            });
        }

        static bool VerifyGenericArg(MethodSpec gim, ElementType etype)
        {
            if (gim == null)
                return false;
            var gims = gim.GenericInstMethodSig;
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