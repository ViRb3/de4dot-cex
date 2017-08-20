using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using FieldAttributes = dnlib.DotNet.FieldAttributes;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using TypeAttributes = dnlib.DotNet.TypeAttributes;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class ResourceDecrypter
    {
        private FieldDef _arrayField, _asmField;

        private byte[] _decryptedBytes;
        private readonly ISimpleDeobfuscator _deobfuscator;
        private readonly MethodDef _lzmaMethod;

        private readonly ModuleDef _module;

        public ResourceDecrypter(ModuleDef module, MethodDef lzmaMethod, ISimpleDeobfuscator deobfsucator)
        {
            this._module = module;
            this._lzmaMethod = lzmaMethod;
            _deobfuscator = deobfsucator;
        }

        public bool CanRemoveLzma { get; private set; }

        public TypeDef Type { get; private set; }
        public MethodDef Method { get; private set; }
        public MethodDef AssembyResolveMethod { get; private set; }
        public List<FieldDef> Fields => new List<FieldDef> {_arrayField, _asmField};

        public bool Detected => Method != null && _decryptedBytes != null && _arrayField != null && _asmField != null;

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
                var method = inst.Operand as MethodDef;
                if (!method.HasBody || !method.IsStatic)
                    continue;
                if (!DotNetUtils.IsMethod(method, "System.Void", "()"))
                    continue;
                
                _deobfuscator.Deobfuscate(method, SimpleDeobfuscatorFlags.Force);
                
                if (!IsResDecryptInit(method, out FieldDef aField, out FieldDef asmField, out MethodDef mtd))
                    continue;
                
                try
                {
                    _decryptedBytes = DecryptArray(method, aField.InitialValue);
                }
                catch(Exception e)
                {
	                Console.WriteLine(e.Message);
                    return;
                }
                
                _arrayField = aField;
                Type = DotNetUtils.GetType(_module, aField.FieldSig.Type);
                _asmField = asmField;
                AssembyResolveMethod = mtd;   
                Method = method;      
	            CanRemoveLzma = true;
            }
        }

        private bool IsResDecryptInit(MethodDef method, out FieldDef aField, out FieldDef asField, out MethodDef mtd)
        {
            aField = null;
            asField = null;
            mtd = null;
            var instr = method.Body.Instructions;
            if (instr.Count < 15)
                return false;

            if (!instr[0].IsLdcI4())
                return false;
            if (!instr[1].IsStloc()) //uint num = 96u;
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
            aField = instr[5].Operand as FieldDef;
            if (aField?.InitialValue == null)
                return false;
            if (aField.Attributes != (FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.HasFieldRVA))
                return false;
            if (instr[6].OpCode != OpCodes.Call)
                return false;
            if (instr[6].Operand.ToString() !=
                "System.Void System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(System.Array,System.RuntimeFieldHandle)"
            )
                return false;
            if (!instr[7].IsStloc()) // uint[] array = new uint[] {.....};
                return false;

            var l = instr.Count;
            if (!instr[l - 10].IsLdloc())
                return false;
            if (instr[l - 9].OpCode != OpCodes.Call)
                return false;
            if (instr[l - 9].Operand != _lzmaMethod)
                return false;
            if (instr[l - 8].OpCode != OpCodes.Call)
                return false;
            if (instr[l - 8].Operand.ToString() !=
                "System.Reflection.Assembly System.Reflection.Assembly::Load(System.Byte[])")
                return false;
            if (instr[l - 7].OpCode != OpCodes.Stsfld) //<Module>.assembly_0 = Assembly.Load(array4);
                return false;
            asField = instr[l - 7].Operand as FieldDef;
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
            mtd = instr[l - 4].Operand as MethodDef;
            if (mtd == null)
                return false;
            
            if (DotNetUtils.IsMethod(mtd, "", "()"))
                return false;
            
            _deobfuscator.Deobfuscate(mtd, SimpleDeobfuscatorFlags.Force);     
            
            if (!IsAssembyResolveMethod(mtd, asField))
                return false;
            
            if (instr[l - 3].OpCode != OpCodes.Newobj)
                return false;
            if (instr[l - 2].OpCode != OpCodes.Callvirt)
                //AppDomain.CurrentDomain.AssemblyResolve += new ResolveEventHandler(<Module>.smethod_1);
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

            for (int i = 0; i < 8; i++)
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

	    private bool IsAssembyResolveMethod(MethodDef method, FieldDef field)
        {
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
                newModule = ModuleDefMD.Load(_decryptedBytes);
            }
            catch
            {
                CanRemoveLzma = false;
                return;
            }
            var toRemove = new List<Resource>();
            var toAdd = new List<Resource>();
            foreach (var cryptedResource in _module.Resources)
            foreach (var resource in newModule.Resources)
                if (cryptedResource.Name == resource.Name)
                {
                    toRemove.Add(cryptedResource);
                    toAdd.Add(resource);
                }

            foreach (var resToRemove in toRemove)
                _module.Resources.Remove(resToRemove);
            foreach (var resToAdd in toAdd)
                _module.Resources.Add(resToAdd);
        }
    }
}