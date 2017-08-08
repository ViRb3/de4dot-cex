using System;
using System.Collections.Generic;
using System.Linq;
using de4dot.blocks;
using de4dot.blocks.cflow;
using de4dot.code.deobfuscators.ConfuserEx.x86;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    internal class Context
    {
        public int ByteNum;
        public MethodDef CreateMethod;
        public uint FieldToken;

        public Context(uint fieldToken, int byteNum, MethodDef createMethod)
        {
            FieldToken = fieldToken;
            ByteNum = byteNum; // 2nd parameter of the Delegate CreateMethod
            CreateMethod = createMethod;
        }
    }

    internal class ProxyCallFixer : ProxyCallFixer4
    {
        private readonly InstructionEmulator _instructionEmulator = new InstructionEmulator();
        private readonly List<MethodDef> _processedMethods = new List<MethodDef>();
        private readonly ISimpleDeobfuscator _simpleDeobfuscator;
        public List<TypeDef> AttributeTypes = new List<TypeDef>();
        public List<MethodDef> DelegateCreatorMethods = new List<MethodDef>();
        public List<MethodDef> NativeMethods = new List<MethodDef>();

        public ProxyCallFixer(ModuleDefMD module, ISimpleDeobfuscator simpleDeobfuscator) : base(module)
        {
            _simpleDeobfuscator = simpleDeobfuscator;
        }

        public ProxyCallFixer(ModuleDefMD module, ProxyCallFixer4 oldOne) : base(module, oldOne)
        {
        }

        protected override object CheckCctor(TypeDef type, MethodDef cctor)
        {
            if (!_processedMethods.Contains(cctor))
            {
                _simpleDeobfuscator.Deobfuscate(cctor);
                _processedMethods.Add(cctor);
            }

            var contexts = new List<Context>();
            var instructions = cctor.Body.Instructions;
            instructions.SimplifyMacros(cctor.Body.Variables, cctor.Parameters);
            for (var i = 0; i < instructions.Count; i++)
            {
                var instrs =
                    DotNetUtils.GetInstructions(instructions, i, OpCodes.Ldtoken, OpCodes.Ldc_I4, OpCodes.Call);
                if (instrs == null)
                    continue;

                var fieldToken = ((IField) instrs[0].Operand).MDToken.ToUInt32();
                var byteNum = (int) instrs[1].Operand;
                var createMethod = instrs[2].Operand as MethodDef;

                if (!DelegateCreatorMethods.Contains(createMethod))
                    DelegateCreatorMethods.Add(createMethod);

                contexts.Add(new Context(fieldToken, byteNum, createMethod));
            }
            return contexts.Count == 0 ? null : contexts;
        }

        private void DeobfuscateIfNeeded(MethodDef method)
        {
            if (!_processedMethods.Contains(method))
            {
                _simpleDeobfuscator.Deobfuscate(method);
                _processedMethods.Add(method);
            }
        }

        private byte[] GetExtraDataToken(byte[] sigData)
        {
            var extraData = new byte[4];

            // [original signature] [extra signature]
            //         ...             X C0 X X X
            Array.Copy(sigData, sigData.Length - 3, extraData, 1, 3); // last 3 bytes of signature
            extraData[0] = sigData[sigData.Length - 5]; // the byte before C0
            Array.Reverse(extraData); // decryptorMethod reads the bytes backwards
            return extraData;
        }

        protected override void GetCallInfo(object context, FieldDef field, out IMethod calledMethod,
            out OpCode callOpcode)
        {
            var contexts = (List<Context>) context;
            var ctx = contexts.First(c => c.FieldToken == field.MDToken.ToInt32());
            var originalMethod =
                DotNetUtils.Clone(ctx
                    .CreateMethod); // backup original method and restore because changes are not universal
            DeobfuscateIfNeeded(ctx.CreateMethod);

            var instructions = ctx.CreateMethod.Body.Instructions;
            var variables = ctx.CreateMethod.Body.Variables;
            var parameters = ctx.CreateMethod.Parameters;

            instructions.SimplifyMacros(variables, parameters);
            var sigData = module.ReadBlob(ctx.FieldToken);
            var extraDataToken = GetExtraDataToken(sigData);
            var modifierMDToken = ((CModOptSig) field.FieldType).Modifier.MDToken.ToInt32();

            ReplaceMetadataToken(ref instructions, modifierMDToken, variables[0]);
            ReplaceFieldNameChars(ref instructions, field.Name, variables[0]);
            InlineArrays(ref instructions, extraDataToken, variables[1], variables[2]);
            RemoveDecrementorBlock(ref instructions, variables[2]);

            var firstInstruction = GetEmulationStartIndex(instructions, variables[1], variables[2]);
            var lastInstruction =
                instructions.IndexOf(
                    instructions.First(
                        i => i.OpCode == OpCodes.Callvirt && i.Operand.ToString().Contains("GetCustomAttributes"))) - 4;

            var nativeMode = false;
            if (instructions[lastInstruction - 1].OpCode == OpCodes.Call) // x86 protection
            {
                lastInstruction--; // don't try emulating native method
                nativeMode = true;
            }

            var result = EmulateManagedMethod(ctx.CreateMethod, firstInstruction, lastInstruction);
            if (nativeMode)
            {
                var nativeMethod = (MethodDef) instructions[lastInstruction].Operand;
                if (!NativeMethods.Contains(nativeMethod))
                    NativeMethods.Add(nativeMethod);
                result = EmulateNativeMethod(nativeMethod, result);
            }

            result *= GetMagicNumber(field.CustomAttributes[0]);
            calledMethod = module.ResolveMemberRef(new MDToken(result).Rid);

            if (calledMethod == null)
                throw new Exception();

            var charNum = GetCharNum(instructions, parameters.Last());
            callOpcode = GetCallOpCode(calledMethod, charNum, ctx.ByteNum);

            ctx.CreateMethod.Body = originalMethod.Body; // restore
        }

        private OpCode GetCallOpCode(IMethod calledMethod, int charNum, int byteNum)
        {
            if (calledMethod.ResolveMethodDef().IsStatic) return OpCodes.Call;

            var charOpCode = (byte) (charNum ^ byteNum);

            if (charOpCode == 0x28)
                return OpCodes.Call;
            if (charOpCode == 0x6F)
                return OpCodes.Callvirt;
            if (charOpCode == 0x73)
                return OpCodes.Newobj;
            throw new Exception();
        }

        private int EmulateNativeMethod(MethodDef externalMethod, int parameter)
        {
            var nativeMethod = new X86Method(externalMethod, module); //TODO: Possible null
            return nativeMethod.Execute(parameter);
        }

        private int EmulateManagedMethod(MethodDef method, int startIndex, int endIndex,
            params Tuple<Parameter, int>[] parameters)
        {
            _instructionEmulator.Initialize(method, false);
            foreach (var parameter in parameters)
                _instructionEmulator.SetArg(parameter.Item1, new Int32Value(parameter.Item2));

            for (var i = startIndex; i < endIndex; i++) _instructionEmulator.Emulate(method.Body.Instructions[i]);

            return ((Int32Value) _instructionEmulator.Pop()).Value;
        }

        private int GetMagicNumber(CustomAttribute customAttribute)
        {
            var attributeType = customAttribute.AttributeType.ResolveTypeDef();
            if (!AttributeTypes.Contains(attributeType))
                AttributeTypes.Add(attributeType);

            var ctor = attributeType.FindConstructors().First();
            DeobfuscateIfNeeded(ctor);

            var magicNum = Convert.ToInt32(customAttribute.ConstructorArguments[0].Value);
            var parameter = new Tuple<Parameter, int>();
            parameter.Item1 = ctor.Parameters[1];
            parameter.Item2 = magicNum;

            return EmulateManagedMethod(ctor, 3, ctor.Body.Instructions.Count - 2, parameter);
        }

        public void FindDelegateCreatorMethod()
        {
            var globalType = module.GlobalType;
            foreach (
                var method in
                globalType.Methods.Where(
                    m => m.Parameters.Count == 2 && m.Parameters[0].Type.TypeName == "RuntimeFieldHandle"))
            {
                _simpleDeobfuscator.Deobfuscate(method);
                SetDelegateCreatorMethod(method);
            }
        } //TODO: Improve detection


        /* 0x000005B7 6F1500000A    IL_001F: callvirt instance uint8[][mscorlib] System.Reflection.Module::ResolveSignature(int32)
	       0x000005BC FE0E0100      IL_0024: stloc.1
	       0x000005C0 FE0C0100      IL_0028: ldloc.1
	       0x000005C4 8E            IL_002C: ldlen
	       0x000005C5 69            IL_002D: conv.i4
	       0x000005C6 FE0E0200      IL_002E: stloc.2 */
        private int GetEmulationStartIndex(IList<Instruction> instructions, Local localArray, Local localArraySize)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                var instrs = DotNetUtils.GetInstructions(instructions, i, OpCodes.Callvirt, OpCodes.Stloc,
                    OpCodes.Ldloc, OpCodes.Ldlen, OpCodes.Conv_I4, OpCodes.Stloc);

                if (instrs == null)
                    continue;
                if (!instrs[0].Operand.ToString().Contains("ResolveSignature"))
                    continue;
                if ((Local) instrs[1].Operand != localArray)
                    continue;
                if ((Local) instrs[2].Operand != localArray)
                    continue;
                if ((Local) instrs[5].Operand != localArraySize)
                    continue;

                return i + 6;
            }
            return -1;
        }

        /* 0x000008F3 03            IL_02BB: ldarg.1
	       0x000008F4 61            IL_02BC: xor */
        private int GetCharNum(IList<Instruction> instructions, Parameter byteParam)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                var instrs = DotNetUtils.GetInstructions(instructions, i, OpCodes.Ldarg, OpCodes.Xor);

                if (instrs == null)
                    continue;
                if ((Parameter) instrs[0].Operand != byteParam)
                    continue;

                return (int) instructions[i - 5].Operand;
            }
            throw new Exception();
        }


        private void ReplaceFieldNameChars(ref IList<Instruction> instructions, string fieldName, Local fieldLocal)
        {
            bool foundInstrs;
            do
            {
                foundInstrs = ReplaceFieldNameChar(ref instructions, fieldName, fieldLocal);
            } while (foundInstrs);
        }

        /* 0x00000375 06            IL_007D: ldloc.0
           0x00000376 6F1500000A    IL_007E: callvirt
           0x0000037B 19            IL_0083: ldc.i4.3
           0x0000037C 6F1600000A    IL_0084: callvirt */
        private bool ReplaceFieldNameChar(ref IList<Instruction> instructions, string fieldName, Local fieldLocal)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                var instrs = DotNetUtils.GetInstructions(instructions, i, OpCodes.Ldloc, OpCodes.Callvirt,
                    OpCodes.Ldc_I4, OpCodes.Callvirt);

                if (instrs == null)
                    continue;
                if ((Local) instrs[0].Operand != fieldLocal)
                    continue;
                if (!instrs[1].Operand.ToString().Contains("get_Name"))
                    continue;
                if (!instrs[3].Operand.ToString().Contains("get_Chars"))
                    continue;

                var charIndex = (int) instrs[2].Operand;
                int @char = fieldName[charIndex];

                instructions[i].OpCode = OpCodes.Ldc_I4;
                instructions[i].Operand = @char;
                instructions[i + 1].OpCode = OpCodes.Nop;
                instructions[i + 2].OpCode = OpCodes.Nop;
                instructions[i + 3].OpCode = OpCodes.Nop;
                return true;
            }
            return false;
        }

        /* 0x0000034A 08            IL_0052: ldloc.2
	       0x0000034B 17            IL_0053: ldc.i4.1
	       0x0000034C 59            IL_0054: sub
           0x0000034D 25            IL_0055: dup
           0x0000034E 0C            IL_0056: stloc.2
	       0x0000034F 91            IL_0057: ldelem.u1 */
        private void InlineArrays(ref IList<Instruction> instructions, byte[] values, Local localArray, Local localInt)
        {
            bool foundInstrs;
            var i = 0;
            do
            {
                foundInstrs = InlineArray(ref instructions, values[i++], localArray, localInt);
            } while (i < 4 && foundInstrs);
        }

        private bool InlineArray(ref IList<Instruction> instructions, int value, Local localArray, Local localInt)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                var instrs = DotNetUtils.GetInstructions(instructions, i, OpCodes.Ldloc, OpCodes.Ldloc, OpCodes.Ldc_I4,
                    OpCodes.Sub, OpCodes.Dup, OpCodes.Stloc, OpCodes.Ldelem_U1);

                if (instrs == null)
                    continue;
                if ((Local) instrs[0].Operand != localArray)
                    continue;
                if ((Local) instrs[1].Operand != localInt)
                    continue;
                if ((int) instrs[2].Operand != 1)
                    continue;
                if ((Local) instrs[5].Operand != localInt)
                    continue;

                instructions[i].OpCode = OpCodes.Ldc_I4;
                instructions[i].Operand = value;
                instructions[i + 1].OpCode = OpCodes.Nop;
                instructions[i + 2].OpCode = OpCodes.Nop;
                instructions[i + 3].OpCode = OpCodes.Nop;
                instructions[i + 4].OpCode = OpCodes.Nop;
                instructions[i + 5].OpCode = OpCodes.Nop;
                instructions[i + 6].OpCode = OpCodes.Nop;
                return true;
            }
            return false;
        }

        /* 0x00000371 08            IL_0079: ldloc.2
	       0x00000372 17            IL_007A: ldc.i4.1
	       0x00000373 59            IL_007B: sub
           0x00000374 0C            IL_007C: stloc.2 */
        private void RemoveDecrementorBlock(ref IList<Instruction> instructions, Local localInt)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                var instrs = DotNetUtils.GetInstructions(instructions, i, OpCodes.Ldloc, OpCodes.Ldc_I4, OpCodes.Sub,
                    OpCodes.Stloc);

                if (instrs == null)
                    continue;
                if ((Local) instrs[0].Operand != localInt)
                    continue;
                if ((int) instrs[1].Operand != 1)
                    continue;
                if ((Local) instrs[3].Operand != localInt)
                    continue;

                instructions[i].OpCode = OpCodes.Nop;
                instructions[i + 1].OpCode = OpCodes.Nop;
                instructions[i + 2].OpCode = OpCodes.Nop;
                instructions[i + 3].OpCode = OpCodes.Nop;
                return;
            }
        }

        /* 0x000005CF FE0C0000      IL_0037: ldloc.0
	       0x000005D3 6F1600000A    IL_003B: callvirt instance class [mscorlib] System.Type[][mscorlib] System.Reflection.FieldInfo::GetOptionalCustomModifiers()
           0x000005D8 2000000000    IL_0040: ldc.i4.0
	       0x000005DD 9A            IL_0045: ldelem.ref
           0x000005DE 6F1400000A    IL_0046: callvirt instance int32[mscorlib] System.Reflection.MemberInfo::get_MetadataToken() */
        private void ReplaceMetadataToken(ref IList<Instruction> instructions, int metadataToken, Local fieldLocal)
        {
            for (var i = 0; i < instructions.Count; i++)
            {
                var instrs = DotNetUtils.GetInstructions(instructions, i, OpCodes.Ldloc, OpCodes.Callvirt,
                    OpCodes.Ldc_I4,
                    OpCodes.Ldelem_Ref, OpCodes.Callvirt);

                if (instrs == null)
                    continue;
                if ((Local) instrs[0].Operand != fieldLocal)
                    continue;
                if (!instrs[1].Operand.ToString().Contains("GetOptionalCustomModifiers"))
                    continue;
                if ((int) instrs[2].Operand != 0)
                    continue;
                if (!instrs[4].Operand.ToString().Contains("get_MetadataToken"))
                    continue;

                instructions[i].OpCode = OpCodes.Ldc_I4;
                instructions[i].Operand = metadataToken;
                instructions[i + 1].OpCode = OpCodes.Nop;
                instructions[i + 2].OpCode = OpCodes.Nop;
                instructions[i + 3].OpCode = OpCodes.Nop;
                instructions[i + 4].OpCode = OpCodes.Nop;
                return;
            }
        }
    }
}