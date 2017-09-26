using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public static class Utils
    {
        public static bool IsArithmetical(this Instr instr)
        {
            switch (instr.OpCode.Code)
            {
                case Code.Add:
                case Code.Add_Ovf:
                case Code.Add_Ovf_Un:
                case Code.Div:
                case Code.Div_Un:
                case Code.Mul:
                case Code.Mul_Ovf:
                case Code.Mul_Ovf_Un:
                case Code.Not:
                case Code.Shl:
                case Code.Shr:
                case Code.Shr_Un:
                case Code.Sub:
                case Code.Sub_Ovf:
                case Code.Sub_Ovf_Un:
                case Code.Xor:
                case Code.And:
                case Code.Rem:
                case Code.Rem_Un:
                case Code.Ceq:
                case Code.Cgt:
                case Code.Cgt_Un:
                case Code.Clt:
                case Code.Clt_Un:
                case Code.Neg:
                case Code.Or:
                    return true;
            }
            return false;
        }

        public static bool IsConv(this Instr instr)
        {
            switch (instr.OpCode.Code)
            {
                case Code.Conv_I1:
                case Code.Conv_I2:
                case Code.Conv_I4:
                case Code.Conv_I8:
                case Code.Conv_U1:
                case Code.Conv_U2:
                case Code.Conv_U4:
                case Code.Conv_U8:
                case Code.Conv_R4:
                case Code.Conv_R8:
                case Code.Conv_Ovf_I1:
                case Code.Conv_Ovf_I1_Un:
                case Code.Conv_Ovf_I2:
                case Code.Conv_Ovf_I2_Un:
                case Code.Conv_Ovf_I4:
                case Code.Conv_Ovf_I4_Un:
                case Code.Conv_Ovf_I8:
                case Code.Conv_Ovf_I8_Un:
                case Code.Conv_Ovf_U1:
                case Code.Conv_Ovf_U1_Un:
                case Code.Conv_Ovf_U2:
                case Code.Conv_Ovf_U2_Un:
                case Code.Conv_Ovf_U4:
                case Code.Conv_Ovf_U4_Un:
                case Code.Conv_Ovf_U8:
                case Code.Conv_Ovf_U8_Un:
                    return true;
            }
            return false;
        }

        public static bool IsLdc(this Instr instr)
        {
            switch (instr.OpCode.Code)
            {
                case Code.Ldc_I4:
                case Code.Ldc_I4_S:
                case Code.Ldc_I4_0:
                case Code.Ldc_I4_1:
                case Code.Ldc_I4_2:
                case Code.Ldc_I4_3:
                case Code.Ldc_I4_4:
                case Code.Ldc_I4_5:
                case Code.Ldc_I4_6:
                case Code.Ldc_I4_7:
                case Code.Ldc_I4_8:
                case Code.Ldc_I4_M1:
                case Code.Ldc_I8:
                case Code.Ldc_R4:
                case Code.Ldc_R8:
                    return true;
            }
            return false;
        }

        public static bool IsLoc(this Instr instr)
        {
            switch (instr.OpCode.Code)
            {
                case Code.Ldloc:
                case Code.Ldloc_S:
                case Code.Ldloc_0:
                case Code.Ldloc_1:
                case Code.Ldloc_2:
                case Code.Ldloc_3:
                case Code.Ldloca:
                case Code.Ldloca_S:
                case Code.Stloc:
                case Code.Stloc_S:
                case Code.Stloc_0:
                case Code.Stloc_1:
                case Code.Stloc_2:
                case Code.Stloc_3:
                    return true;
            }
            return false;
        }

        public static bool IsValidInstr(this Instr instr)
        {
            return IsArithmetical(instr) || instr.IsConv() || IsLdc(instr) || IsLoc(instr) ||
                   instr.OpCode == OpCodes.Dup;
        }

        public static bool IsDup(this Block block)
        {
            if (block.Sources.Count != 1)
                return false;
            if (block.Instructions.Count != 2)
                return false;
            if (!block.FirstInstr.IsLdcI4())
                return false;
            if (block.LastInstr.OpCode != OpCodes.Dup)
                if (!block.LastInstr.IsLdcI4() || block.LastInstr.GetLdcI4Value() != block.FirstInstr.GetLdcI4Value())
                    return false;
            return true;
        }
        
        public static MethodDefUser Clone(MethodDef origin)
        {
            var ret = new MethodDefUser(origin.Name, origin.MethodSig, origin.ImplAttributes, origin.Attributes);

            foreach (GenericParam genericParam in origin.GenericParameters)
                ret.GenericParameters.Add(new GenericParamUser(genericParam.Number, genericParam.Flags, "-"));

            ret.Body = origin.Body;
            return ret;
        }
        
        public static T[] ConvertArray<T, T1>(T1[] array)
        {
            var l = Marshal.SizeOf(typeof(T));
            var l1 = Marshal.SizeOf(typeof(T1));
            var buffer = new T[array.Length * l1 / l];
            Buffer.BlockCopy(array, 0, buffer, 0, array.Length * l1);
            return buffer;
        }
    }

    public static class Extensions
    {
        public static bool IsTernaryPredicate(this Block ternaryPredicateBlock)
        {
            if (!ternaryPredicateBlock.LastInstr.IsConditionalBranch())
                return false;

            if (ternaryPredicateBlock.CountTargets() > 2)
                return false;

            var source1 = ternaryPredicateBlock.Targets[0];
            var source2 = ternaryPredicateBlock.FallThrough;

            //if (!IsDup(source1) || !IsDup(source2))
            //    return false;

            if (source1.CountTargets() > 1 || source2.CountTargets() > 1)
                return false;

            var mainBlock = source1.FallThrough;

            if (mainBlock != source2.FallThrough)
                return false;

            if (mainBlock.Sources.Count != 2)
                return false;
            if (mainBlock.LastInstr.OpCode == OpCodes.Ret)
                return false;

            return true;
        }

        public static bool IsTernary(this Block block)
        {
            var sources = block.Sources;
            if (sources.Count != 2)
                return false;
            if (!sources[0].IsDup() || !sources[1].IsDup()) //TODO: Case without DUP?
                return false;
            if (sources[0].CountTargets() > 1 || sources[1].CountTargets() > 1)
                return false;
            if (sources[0].FallThrough != block || sources[1].FallThrough != block)
                return false;
            if (sources[0].Sources[0] != sources[1].Sources[0])
                return false;
            if (!sources[0].Sources[0].IsConditionalBranch())
                return false;
            if (block.LastInstr.OpCode == OpCodes.Ret)
                return false;

            return true;
        }

        public static List<Block> GetTernaryPredicates(this List<Block> switchCaseBlocks)
        {
            var ternaryPredicates = new List<Block>();

            foreach (var preBlock in switchCaseBlocks)
                if (IsTernary(preBlock)) // switchCaseBlock -> 2x sourceBlock -> ternaryPredicateBlock
                    ternaryPredicates.Add(preBlock.Sources[0].Sources[0]);

            return ternaryPredicates;
        }

        public static Block GetTernaryPredicateMainBlock(this Block ternaryPredicateBlock)
        {
            return ternaryPredicateBlock.FallThrough.FallThrough;
        }
    }
}