using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class ResourceDecrypter
    {
        TypeDef arrayType;
        MethodDef resourceDecInitMethod, assembyResolveMethod;
        FieldDef arrayField, asmField;
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
            get { return resourceDecInitMethod; }
        }
        public MethodDef AssembyResolveMethod
        {
            get { return assembyResolveMethod; }
        }
        public List<FieldDef> Fields
        {
            get { return new List<FieldDef>() { arrayField, asmField }; }
        }
        public bool Detected
        {
            get
            {
                return resourceDecInitMethod != null && resourceDecInitMethod != null
                  && decryptedBytes != null && arrayField != null && asmField != null;
            }
        }

        ModuleDef module;
        MethodDef lzmaMethod;
        ISimpleDeobfuscator deobfuscator;
        public ResourceDecrypter(ModuleDef module, MethodDef lzmaMethod, ISimpleDeobfuscator deobfsucator)
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
                if (!isResDecryptInit(method))
                    continue;
                resourceDecInitMethod = method;
            }
        }

        bool isResDecryptInit(MethodDef method)
        {
            var instr = method.Body.Instructions;

            if (instr.Count < 15)
                return false;

            if (!instr[0].IsLdcI4())
                return false;
            if (!instr[1].IsStloc())  //uint num = 96u;
                return false;

            if (!instr[2].IsLdcI4())
                return false;
            if (instr[0].GetLdcI4Value() != instr[2].GetLdcI4Value())
                return false;
            if (instr[3].OpCode != OpCodes.Newarr)
                return false;
            if (instr[3].Operand.ToString() != "System.UInt32")
                return false;
            if (instr[4].OpCode != OpCodes.Dup)
                return false;
            if (instr[5].OpCode != OpCodes.Ldtoken)
                return false;
            var aField = instr[5].Operand as FieldDef;
            if (aField == null)
                return false;
            if (aField.InitialValue == null)
                return false;
            if (aField.Attributes != (FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA))
                return false;
            if (instr[6].OpCode != OpCodes.Call)
                return false;
            if (instr[6].Operand.ToString() != "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)")
                return false;
            if (!instr[7].IsStloc())  // uint[] array = new uint[] {.....};
                return false;

            var l = instr.Count;
            if (!instr[l - 10].IsLdloc())
                return false;
            if (instr[l - 9].OpCode != OpCodes.Call)
                return false;
            if (instr[l - 9].Operand != lzmaMethod)
                return false;
            if (instr[l - 8].OpCode != OpCodes.Call)
                return false;
            if (instr[l - 8].Operand.ToString() != "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])")
                return false;
            if (instr[l - 7].OpCode != OpCodes.Stsfld)  //<Module>.assembly_0 = Assembly.Load(array4);
                return false;
            var asField = instr[l - 7].Operand as FieldDef;
            if (asField == null)
                return false;

            if (instr[l - 6].OpCode != OpCodes.Call)
                return false;
            if (instr[l - 6].Operand.ToString() != "System.AppDomain System.AppDomain::get_CurrentDomain()")
                return false;
            if (instr[l - 5].OpCode != OpCodes.Ldnull)
                return false;
            if (instr[l - 4].OpCode != OpCodes.Ldftn)
                return false;
            var mtd = instr[l - 4].Operand as MethodDef;
            if (mtd == null)
                return false;
            if (!IsAssembyResolveMethod(mtd, asField))
                return false;
            if (instr[l - 3].OpCode != OpCodes.Newobj)
                return false;
            if (instr[l - 2].OpCode != OpCodes.Callvirt)  //AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(<Module>.smethod_1);
                return false;
            try
            {
                DecryptArray(ConvertArray<uint, byte>(aField.InitialValue));
            }
            catch { canRemoveLzma = false; return false; }
            arrayField = aField;
            arrayType = DotNetUtils.GetType(module, aField.FieldSig.Type);
            asmField = asField;
            assembyResolveMethod = mtd;
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
        private void DecryptArray(uint[] array) //TODO: Automatic detection
        {
            int num = array.Length;
            uint[] array2 = new uint[16];
            uint num2 = 825993394u;
            for (int i = 0; i < 16; i++)
            {
                num2 ^= num2 >> 13;
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
                array3[0] = (array3[0] ^ array2[0]);
                array3[1] = (array3[1] ^ array2[1]);
                array3[2] = (array3[2] ^ array2[2]);
                array3[3] = (array3[3] ^ array2[3]);
                array3[4] = (array3[4] ^ array2[4]);
                array3[5] = (array3[5] ^ array2[5]);
                array3[6] = (array3[6] ^ array2[6]);
                array3[7] = (array3[7] ^ array2[7]);
                array3[8] = (array3[8] ^ array2[8]);
                array3[9] = (array3[9] ^ array2[9]);
                array3[10] = (array3[10] ^ array2[10]);
                array3[11] = (array3[11] ^ array2[11]);
                array3[12] = (array3[12] ^ array2[12]);
                array3[13] = (array3[13] ^ array2[13]);
                array3[14] = (array3[14] ^ array2[14]);
                array3[15] = (array3[15] ^ array2[15]);
                for (int k = 0; k < 16; k++)
                {
                    uint num5 = array3[k];
                    array4[num4++] = (byte)num5;
                    array4[num4++] = (byte)(num5 >> 8);
                    array4[num4++] = (byte)(num5 >> 16);
                    array4[num4++] = (byte)(num5 >> 24);
                    array2[k] ^= num5;
                }
                num3 += 16;
            }
            decryptedBytes = Lzma.Decompress(array4);
        }

        private bool IsAssembyResolveMethod(MethodDef method, FieldDef field)
        {
            if (DotNetUtils.IsMethod(method, "", "()"))
                return false;
            deobfuscator.Deobfuscate(method, SimpleDeobfuscatorFlags.Force);

            var instr = method.Body.Instructions;
            if (instr.Count != 10)
                return false;

            if (instr[0].OpCode != OpCodes.Ldsfld)
                return false;
            if (instr[0].Operand != field)
                return false;
            if (instr[1].OpCode != OpCodes.Callvirt)
                return false;
            if (instr[1].Operand.ToString() != "System.String System.Reflection.Assembly::get_FullName()")
                return false;
            if (!instr[2].IsLdarg())
                return false;
            if (instr[3].OpCode != OpCodes.Callvirt)
                return false;
            if (instr[3].Operand.ToString() != "System.String System.ResolveEventArgs::get_Name()")
                return false;
            if (instr[4].OpCode != OpCodes.Call)
                return false;
            if (instr[4].Operand.ToString() != "System.Boolean System.String::op_Equality(System.String,System.String)")
                return false;
            if (!instr[5].IsBrfalse())
                return false;
            if (instr[6].OpCode != OpCodes.Ldsfld)
                return false;
            if (instr[6].Operand != field)
                return false;
            if (instr[7].OpCode != OpCodes.Ret)
                return false;
            if (instr[8].OpCode != OpCodes.Ldnull)
                return false;
            if (instr[9].OpCode != OpCodes.Ret)
                return false;
            return true;
        }

        public void Fix()
        {
            ModuleDef newModule;
            try
            {
                newModule = ModuleDefMD.Load(decryptedBytes);
            }
            catch { canRemoveLzma = false; return; }
            List<Resource> toRemove = new List<Resource>();
            List<Resource> toAdd = new List<Resource>();
            foreach (var cryptedResource in module.Resources)
                foreach (var resource in newModule.Resources)
                    if (cryptedResource.Name == resource.Name)
                    {
                        toRemove.Add(cryptedResource);
                        toAdd.Add(resource);
                    }

            foreach (var resToRemove in toRemove)
                module.Resources.Remove(resToRemove);
            foreach (var resToAdd in toAdd)
                module.Resources.Add(resToAdd);
        }
    }
}