using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using de4dot.blocks;
using de4dot.blocks.cflow;
using de4dot.code.deobfuscators.ConfuserEx.x86;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class ConstantDecrypterBase
    {
        private readonly InstructionEmulator _instructionEmulator = new InstructionEmulator();
        private X86Method _nativeMethod;

        public MethodDef Method { get; set; }
        public MethodDef NativeMethod { get; set; }
        public byte[] Decrypted { get; set; }
        public uint Magic1 { get; set; }
        public uint Magic2 { get; set; }
        public bool CanRemove { get; set; } = true;

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
            _instructionEmulator.Push(new Int32Value((int) index));
            _nativeMethod = new X86Method(NativeMethod, Method.Module as ModuleDefMD); //TODO: Possible null
            var key = CalculateKey();

            var uint_0 = (uint) key.Value;
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

        public bool CanRemoveLzma { get; private set; } = true;

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
                if (!IsStringDecrypterInit(method))
                    continue;
                Method = method;
                FindStringDecrypters(moduleCctor.DeclaringType);
            }
        }

        private bool IsStringDecrypterInit(MethodDef method)
        {
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
            var aField = instructions[5].Operand as FieldDef;
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
            var dField = instructions[l - 2].Operand as FieldDef;
            if (dField == null)
                return false;
            try
            {
                DecryptArray(ConvertArray<uint, byte>(aField.InitialValue));
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                CanRemoveLzma = false;
                return false;
            }
            _arrayField = aField;
            ArrayType = DotNetUtils.GetType(_module, aField.FieldSig.Type);
            _decryptedField = dField;
            return true;
        }

        private static T[] ConvertArray<T, T1>(T1[] array)
        {
            var l = Marshal.SizeOf(typeof(T));
            var l1 = Marshal.SizeOf(typeof(T1));
            var buffer = new T[array.Length * l1 / l];
            Buffer.BlockCopy(array, 0, buffer, 0, array.Length * l1);
            return buffer;
        }

        private void DecryptArray(uint[] array) //TODO: Automatic detection
        {
            var num = 1888u; // array size?
            uint[] array2 = new uint[16];
            uint num2 = 3153506350u;
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
                uint num5 = array3[1] << 1;
                uint num6 = array3[1] * 21u;
                array3[2] = (array3[2] ^ array3[10]);
                num5 += array3[1] << 2;
                uint num7 = array3[1] * 21u;
                num6 += array3[0] * 67u;
                uint num8 = array3[1] * 13u;
                num5 += array3[0] * 14u;
                num6 += array3[9] * 157u;
                num8 += array3[0] << 2;
                num5 += array3[9] * 27u;
                array3[13] = array3[13] * 748798011u;
                num8 += array3[0] << 5;
                num7 += array3[0] * 57u;
                num6 += array3[3] * 206u;
                num5 += array3[3] * 43u;
                array3[1] = num5;
                num7 += array3[9] * 133u;
                num8 += array3[9] * 77u;
                num8 += array3[3] * 110u;
                array3[9] = num6;
                num6 = (array3[12] & 1056153664u);
                array3[12] = (array3[12] & 3238813631u);
                array3[0] = num8;
                array3[12] = (array3[12] | (array3[7] & 1056153664u));
                array3[7] = (array3[7] & 3238813631u);
                num8 = array3[2] << 3;
                num5 = array3[8] * 2590225985u;
                num6 *= 770570833u;
                array3[7] = (array3[7] | num6 * 2945289905u);
                array3[8] = array3[4];
                num8 += array3[13] * 50u;
                num7 += array3[3] * 181u;
                array3[0] = array3[0] * 154310079u;
                num6 = (array3[15] & 1073272377u);
                array3[10] = array3[10] - 4001279812u;
                array3[3] = num7;
                array3[15] = (array3[15] & 3221694918u);
                num8 += array3[9] * 67u;
                num7 = array3[5] << 14;
                array3[1] = (array3[1] ^ array2[1]);
                array3[15] = (array3[15] | (array3[11] & 1073272377u));
                array3[5] = array3[5] >> 18;
                array3[12] = (array3[12] ^ array2[12]);
                array3[4] = num5 * 2830588353u;
                array3[11] = (array3[11] & 3221694918u);
                array3[5] = (array3[5] | num7);
                array3[6] = (array3[6] ^ array3[14]);
                num7 = array3[2] << 1;
                num6 *= 918007135u;
                num7 += array3[2];
                array3[11] = (array3[11] | num6 * 3949194911u);
                num5 = array3[2] << 2;
                num7 += array3[13] * 19u;
                num8 += array3[11] << 2;
                num6 = array3[2];
                num6 += array3[13] << 1;
                num6 += array3[13] << 3;
                array3[8] = (array3[8] ^ 4107405834u);
                num7 += array3[9] * 25u;
                num6 += array3[9] * 14u;
                num8 += array3[11] << 7;
                num5 += array3[13] * 38u;
                num6 += array3[11] * 31u;
                array3[3] = (array3[3] ^ array2[3]);
                num5 += array3[9] * 56u;
                array3[1] = array3[1] - 1508476838u;
                array3[3] = (array3[3] ^ 938209744u);
                array3[2] = num6;
                num7 += array3[11] * 49u;
                array3[9] = num8;
                num8 = array3[6] << 1;
                array3[7] = (array3[7] ^ ~array3[15]);
                num8 += array3[6] << 3;
                num5 += array3[11] * 125u;
                array3[0] = (array3[0] ^ array2[0]);
                array3[11] = num5;
                num8 += array3[5] << 5;
                num6 = array3[6] * 11u;
                array3[13] = num7;
                num5 = array3[6] * 55u;
                num8 += array3[5];
                num7 = array3[6] * 54u;
                num8 += array3[3] * 39u;
                num8 += array3[4] << 1;
                num7 += array3[5] * 175u;
                num8 += array3[4] << 5;
                num7 += array3[3] * 209u;
                num5 += array3[5] * 179u;
                num5 += array3[3] * 213u;
                num6 += array3[5] * 35u;
                num7 += array3[4] * 177u;
                num6 += array3[3] * 42u;
                array3[13] = (array3[13] ^ array3[9]);
                num6 += array3[4] << 1;
                num6 += array3[4] << 5;
                array3[7] = (array3[7] ^ array2[7]);
                array3[6] = num6;
                num5 += array3[4] * 181u;
                num6 = array3[14] >> 29;
                array3[3] = num5;
                array3[5] = num8;
                num5 = array3[8] << 2;
                num8 = array3[8] << 2;
                array3[4] = num7;
                array3[14] = array3[14] << 3;
                array3[12] = (array3[12] ^ 2411275161u);
                num8 += array3[8];
                num5 += array3[7] * 7u;
                num5 += array3[6] * 19u;
                num8 += array3[7] * 21u;
                num7 = array3[11] << 24;
                array3[14] = (array3[14] | num6);
                array3[11] = array3[11] >> 8;
                array3[11] = (array3[11] | num7);
                num6 = array3[8] * 11u;
                num5 += array3[13] * 46u;
                num8 += array3[6] * 47u;
                num7 = array3[8];
                num7 += array3[7] << 1;
                num6 += array3[7] * 25u;
                num8 += array3[13] * 109u;
                array3[4] = (array3[4] ^ array2[4]);
                num6 += array3[6] * 63u;
                array3[2] = (array3[2] ^ array3[12]);
                num7 += array3[7] << 2;
                num7 += array3[6] * 13u;
                array3[6] = num5;
                num5 = (array3[0] & 247307561u);
                num5 *= 2926546863u;
                array3[0] = (array3[0] & 4047659734u);
                array3[0] = (array3[0] | (array3[11] & 247307561u));
                num7 += array3[13] * 30u;
                num6 += array3[13] * 150u;
                array3[11] = (array3[11] & 4047659734u);
                array3[11] = (array3[11] | num5 * 1929455439u);
                array3[7] = num8;
                num5 = array3[14] << 20;
                array3[14] = array3[14] >> 12;
                array3[14] = (array3[14] | num5);
                num8 = array3[15] * 19u;
                num5 = array3[3] << 8;
                array3[3] = array3[3] >> 24;
                array3[14] = (array3[14] ^ array2[14]);
                array3[3] = (array3[3] | num5);
                num8 += array3[5] * 69u;
                num5 = array3[15] * 23u;
                array3[8] = num7;
                array3[13] = num6;
                num5 += array3[5] * 86u;
                array3[6] = (array3[6] ^ 3317586132u);
                array3[8] = (array3[8] ^ array2[8]);
                array3[4] = array3[4] - 3314395924u;
                num8 += array3[9] << 1;
                num6 = array3[15] << 2;
                array3[13] = (array3[13] ^ 574204725u);
                num8 += array3[9] << 6;
                num5 += array3[9] * 82u;
                array3[2] = (array3[2] ^ 1681301553u);
                num8 += array3[1] * 76u;
                num7 = array3[15] * 49u;
                num6 += array3[15] << 6;
                array3[15] = num8;
                num7 += array3[5] * 182u;
                num6 += array3[5] * 249u;
                num6 += array3[9] * 239u;
                num7 += array3[9] * 174u;
                num7 += array3[1] * 218u;
                array3[9] = num7;
                num7 = array3[12] << 1;
                num5 += array3[1] * 105u;
                array3[5] = num5;
                num5 = array3[12] << 1;
                num8 = array3[10] >> 2;
                num5 += array3[7] * 7u;
                array3[10] = array3[10] << 30;
                num6 += array3[1] * 285u;
                array3[1] = num6;
                array3[10] = (array3[10] | num8);
                num6 = array3[12] * 28u;
                num7 += array3[12] << 4;
                num7 += array3[7] * 57u;
                num7 += array3[13] * 95u;
                num5 += array3[13] << 2;
                num8 = array3[4] >> 3;
                array3[15] = (array3[15] ^ array2[15]);
                array3[4] = array3[4] << 29;
                array3[4] = (array3[4] | num8);
                num6 += array3[7] * 75u;
                num8 = array3[12] << 1;
                num6 += array3[13] * 113u;
                num5 += array3[13] << 3;
                num8 += array3[12];
                num6 += array3[10] << 1;
                num8 += array3[7] * 11u;
                num7 += array3[10] << 1;
                num7 += array3[10];
                array3[11] = (array3[11] ^ array3[1]);
                num8 += array3[13] << 2;
                array3[7] = num5;
                num8 += array3[13] << 4;
                num5 = array3[9];
                array3[13] = num7;
                array3[12] = num8;
                num8 = array3[9];
                num8 += array3[6] << 1;
                num8 += array3[6];
                array3[0] = array3[0] - array3[15];
                num6 += array3[10] << 3;
                num8 += array3[3] << 3;
                num5 += array3[6] << 4;
                array3[5] = (array3[5] ^ array3[14]);
                array3[10] = num6;
                num6 = array3[9] << 1;
                num5 += array3[3] * 58u;
                num6 += array3[9];
                num8 += array3[3];
                num8 += array3[8] << 2;
                num5 += array3[8] * 23u;
                num7 = 0u + (array3[6] << 1);
                num6 += array3[6] * 13u;
                array3[9] = num8;
                num8 = array3[11] * 3847227639u;
                num6 += array3[3] * 42u;
                num7 += array3[6] << 3;
                num7 += array3[3] * 38u;
                num6 += array3[8] << 1;
                array3[11] = array3[5];
                num6 += array3[8] << 4;
                array3[5] = num8 * 1879390407u;
                num8 = (array3[10] & 3016193462u);
                array3[3] = num5;
                array3[10] = (array3[10] & 1278773833u);
                num5 = array3[14] << 3;
                array3[14] = array3[14] >> 29;
                array3[14] = (array3[14] | num5);
                array3[6] = num6;
                array3[5] = (array3[5] ^ array2[5]);
                num5 = (array3[2] & 1689524702u);
                array3[2] = (array3[2] & 2605442593u);
                array3[10] = (array3[10] | (array3[14] & 3016193462u));
                array3[6] = (array3[6] ^ 1826460809u);
                array3[11] = (array3[11] ^ ~array3[5]);
                num5 *= 1545381913u;
                num7 += array3[8] * 15u;
                array3[8] = num7;
                array3[6] = (array3[6] ^ array2[6]);
                array3[8] = (array3[8] ^ array3[7]);
                num8 *= 3177808341u;
                array3[15] = (array3[15] ^ array3[12]);
                array3[9] = (array3[9] ^ array2[9]);
                array3[11] = (array3[11] ^ array2[11]);
                array3[2] = (array3[2] | (array3[0] & 1689524702u));
                array3[0] = (array3[0] & 2605442593u);
                array3[1] = array3[1] - 504000940u;
                array3[0] = (array3[0] | num5 * 1340355625u);
                array3[2] = (array3[2] ^ array2[2]);
                array3[3] = array3[3] - array3[13];
                num6 = array3[9] >> 30;
                array3[14] = (array3[14] & 1278773833u);
                array3[14] = (array3[14] | num8 * 2270146429u);
                array3[10] = (array3[10] ^ array2[10]);
                num7 = array3[0] << 24;
                array3[9] = array3[9] << 2;
                array3[6] = (array3[6] ^ array3[1]);
                array3[4] = (array3[4] ^ 2605939339u);
                array3[0] = array3[0] >> 8;
                num8 = (array3[3] & 1626864053u);
                array3[6] = array3[6] - array3[1];
                array3[12] = (array3[12] ^ 1401990150u);
                num8 *= 1682859757u;
                array3[8] = array3[8] - 393293234u;
                array3[4] = (array3[4] ^ 2139869331u);
                array3[3] = (array3[3] & 2668103242u);
                array3[3] = (array3[3] | (array3[14] & 1626864053u));
                array3[14] = (array3[14] & 2668103242u);
                array3[9] = (array3[9] | num6);
                array3[14] = (array3[14] | num8 * 2707023589u);
                num5 = array3[9] * 1442504087u;
                num8 = array3[10] * 3851007073u;
                array3[10] = array3[15];
                array3[13] = array3[13] * 2082553177u;
                array3[13] = (array3[13] ^ array2[13]);
                array3[9] = array3[2];
                array3[2] = num5 * 1511879207u;
                array3[0] = (array3[0] | num7);
                array3[15] = num8 * 1163915169u;
                array3[0] = (array3[0] ^ array3[1]);
                array3[13] = (array3[13] ^ array3[7]);
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
            _decryptedBytes = Lzma.Decompress(array4);
        }

        private void FindStringDecrypters(TypeDef type)
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
                IsStringDecrypter(method);
            }
        }

        private void IsStringDecrypter(MethodDef method)
        {
            var instr = method.Body.Instructions;
            if (instr.Count < 25)
                return;

            var i = 0;

            if (!instr[i++].IsLdarg())
                return;

            if (instr[i].OpCode != OpCodes.Call)
                return;

            var nativeMethod = instr[i++].Operand as MethodDef;

            if (nativeMethod == null || !nativeMethod.IsStatic || !nativeMethod.IsNative)
                return;
            if (!DotNetUtils.IsMethod(nativeMethod, "System.Int32", "(System.Int32)"))
                return;

            if (!instr[i++].IsStarg()) //uint_0 = (uint_0 * 2857448701u ^ 1196001109u);
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
            if (!instr[i++].IsStarg()) //uint_0 &= 1073741823u;
                return;

            if (!instr[i++].IsLdarg())
                return;
            if (!instr[i].IsLdcI4() || instr[i++].GetLdcI4Value() != 2)
                return;
            if (instr[i++].OpCode != OpCodes.Shl)
                return;
            if (!instr[i++].IsStarg()) //uint_0 <<= 2;
                return;

            foreach (var mtd in _strDecryptCalledMethods)
                if (!DotNetUtils.CallsMethod(method, mtd))
                    return;
            //TODO: Implement
            //if (!DotNetUtils.LoadsField(method, decryptedField))
            //    return;
            Decrypters.Add(new ConstantDecrypterBase
            {
                Decrypted = _decryptedBytes,
                Method = method,
                NativeMethod = nativeMethod
            });
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