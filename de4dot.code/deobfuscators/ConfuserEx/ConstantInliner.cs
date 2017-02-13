using System.Collections.Generic;
using de4dot.blocks;
using de4dot.blocks.cflow;
using System;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    class ConstantsInliner : IBlocksDeobfuscator
    {
        Blocks blocks;
        SByteValueInliner sbyteValueInliner;
        ByteValueInliner byteValueInliner;
        Int16ValueInliner int16ValueInliner;
        UInt16ValueInliner uint16ValueInliner;
        Int32ValueInliner int32ValueInliner;
        UInt32ValueInliner uint32ValueInliner;
        Int64ValueInliner int64ValueInliner;
        UInt64ValueInliner uint64ValueInliner;
        SingleValueInliner singleValueInliner;
        DoubleValueInliner doubleValueInliner;
        ArrayValueInliner arrayValueInliner;

        public bool ExecuteIfNotModified { get; set; }

        public ConstantsInliner(SByteValueInliner sbyteValueInliner, ByteValueInliner byteValueInliner,
            Int16ValueInliner int16ValueInliner, UInt16ValueInliner uint16ValueInliner, Int32ValueInliner int32ValueInliner,
            UInt32ValueInliner uint32ValueInliner, Int64ValueInliner int64ValueInliner, UInt64ValueInliner uint64ValueInliner,
            SingleValueInliner singleValueInliner, DoubleValueInliner doubleValueInliner, ArrayValueInliner arrayValueInliner)
        {
            this.sbyteValueInliner = sbyteValueInliner;
            this.byteValueInliner = byteValueInliner;
            this.int16ValueInliner = int16ValueInliner;
            this.uint16ValueInliner = uint16ValueInliner;
            this.int32ValueInliner = int32ValueInliner;
            this.uint32ValueInliner = uint32ValueInliner;
            this.int64ValueInliner = int64ValueInliner;
            this.uint64ValueInliner = uint64ValueInliner;
            this.singleValueInliner = singleValueInliner;
            this.doubleValueInliner = doubleValueInliner;
            this.arrayValueInliner = arrayValueInliner;
        }

        public void DeobfuscateBegin(Blocks blocks)
        {
            this.blocks = blocks;
        }

        public bool Deobfuscate(List<Block> allBlocks)
        {
            bool modified = false;
            foreach (var block in allBlocks)
            {
                modified |= sbyteValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= byteValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= int16ValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= uint16ValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= int32ValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= uint32ValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= int64ValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= uint64ValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= singleValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= doubleValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
                modified |= arrayValueInliner.Decrypt(blocks.Method, allBlocks) != 0;
            }
            return modified;
        }
    }
    public class SByteValueInliner : ValueInlinerBase<sbyte>
    {
        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                int num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int)callResult.returnValue));
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, "System.SByte");
                Logger.v("Decrypted sbyte: {0}", callResult.returnValue);
            }
        }
    }
    public class ByteValueInliner : ValueInlinerBase<byte>
    {
        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                int num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int)callResult.returnValue));
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, "System.Byte");
                Logger.v("Decrypted byte: {0}", callResult.returnValue);
            }
        }
    }
    public class Int16ValueInliner : ValueInlinerBase<short>
    {
        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                int num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int)callResult.returnValue));
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, "System.Int16");
                Logger.v("Decrypted int16: {0}", callResult.returnValue);
            }
        }
    }
    public class UInt16ValueInliner : ValueInlinerBase<ushort>
    {
        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                int num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int)callResult.returnValue));
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, "System.UInt16");
                Logger.v("Decrypted uint16: {0}", callResult.returnValue);
            }
        }
    }
    public class UInt32ValueInliner : ValueInlinerBase<uint>
    {
        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                int num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int)callResult.returnValue));
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, "System.UInt32");
                Logger.v("Decrypted uint32: {0}", callResult.returnValue);
            }
        }
    }
    public class UInt64ValueInliner : ValueInlinerBase<ulong>
    {
        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                int num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, OpCodes.Ldc_I8.ToInstruction((long)callResult.returnValue));
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, "System.UInt64");
                Logger.v("Decrypted uint64: {0}", callResult.returnValue);
            }
        }
    }
    public class ArrayValueInliner : ValueInlinerBase<Array>
    {
        InitializedDataCreator initializedDataCreator;

        public ArrayValueInliner(InitializedDataCreator initializedDataCreator) { this.initializedDataCreator = initializedDataCreator; }
        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                int num = callResult.callEndIndex - callResult.callStartIndex + 1;

                var generic = (callResult.GetMethodRef() as MethodSpec).GenericInstMethodSig.GenericArguments;
                ITypeDefOrRef sig = generic[0].Next.ToTypeDefOrRef();

                initializedDataCreator.AddInitializeArrayCode(block, callResult.callStartIndex, num, sig, callResult.returnValue as byte[]);
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, sig.ToString()); //TODO: sig.ToString() ??
                Logger.v("Decrypted array <{1}>: {0}", callResult.returnValue, sig.ToString());
            }
        }
    }
}