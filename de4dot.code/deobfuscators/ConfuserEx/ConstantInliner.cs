using System;
using System.Collections.Generic;
using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    internal class ConstantsInliner : IBlocksDeobfuscator
    {
        private readonly ArrayValueInliner _arrayValueInliner;
        private readonly ByteValueInliner _byteValueInliner;
        private readonly DoubleValueInliner _doubleValueInliner;
        private readonly Int16ValueInliner _int16ValueInliner;
        private readonly Int32ValueInliner _int32ValueInliner;
        private readonly Int64ValueInliner _int64ValueInliner;
        private readonly SByteValueInliner _sbyteValueInliner;
        private readonly SingleValueInliner _singleValueInliner;
        private readonly UInt16ValueInliner _uint16ValueInliner;
        private readonly UInt32ValueInliner _uint32ValueInliner;
        private readonly UInt64ValueInliner _uint64ValueInliner;
        private Blocks _blocks;

        public ConstantsInliner(SByteValueInliner sbyteValueInliner, ByteValueInliner byteValueInliner,
            Int16ValueInliner int16ValueInliner, UInt16ValueInliner uint16ValueInliner,
            Int32ValueInliner int32ValueInliner,
            UInt32ValueInliner uint32ValueInliner, Int64ValueInliner int64ValueInliner,
            UInt64ValueInliner uint64ValueInliner,
            SingleValueInliner singleValueInliner, DoubleValueInliner doubleValueInliner,
            ArrayValueInliner arrayValueInliner)
        {
            _sbyteValueInliner = sbyteValueInliner;
            _byteValueInliner = byteValueInliner;
            _int16ValueInliner = int16ValueInliner;
            _uint16ValueInliner = uint16ValueInliner;
            _int32ValueInliner = int32ValueInliner;
            _uint32ValueInliner = uint32ValueInliner;
            _int64ValueInliner = int64ValueInliner;
            _uint64ValueInliner = uint64ValueInliner;
            _singleValueInliner = singleValueInliner;
            _doubleValueInliner = doubleValueInliner;
            _arrayValueInliner = arrayValueInliner;
        }

        public bool ExecuteIfNotModified { get; set; }

        public void DeobfuscateBegin(Blocks blocks)
        {
            _blocks = blocks;
        }

        public bool Deobfuscate(List<Block> allBlocks)
        {
            var modified = false;
            foreach (var block in allBlocks)
            {
                modified |= _sbyteValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _byteValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _int16ValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _uint16ValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _int32ValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _uint32ValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _int64ValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _uint64ValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _singleValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _doubleValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
                modified |= _arrayValueInliner.Decrypt(_blocks.Method, allBlocks) != 0;
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
                var num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int) callResult.returnValue));
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
                var num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int) callResult.returnValue));
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
                var num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int) callResult.returnValue));
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
                var num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int) callResult.returnValue));
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
                var num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num, Instruction.CreateLdcI4((int) callResult.returnValue));
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
                var num = callResult.callEndIndex - callResult.callStartIndex + 1;

                block.Replace(callResult.callStartIndex, num,
                    OpCodes.Ldc_I8.ToInstruction((long) callResult.returnValue));
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, "System.UInt64");
                Logger.v("Decrypted uint64: {0}", callResult.returnValue);
            }
        }
    }

    public class ArrayValueInliner : ValueInlinerBase<Array>
    {
        private readonly InitializedDataCreator _initializedDataCreator;

        public ArrayValueInliner(InitializedDataCreator initializedDataCreator)
        {
            _initializedDataCreator = initializedDataCreator;
        }

        protected override void InlineReturnValues(IList<CallResult> callResults)
        {
            foreach (var callResult in callResults)
            {
                var block = callResult.block;
                var num = callResult.callEndIndex - callResult.callStartIndex + 1;

                var generic = ((MethodSpec) callResult.GetMethodRef()).GenericInstMethodSig.GenericArguments;
                var sig = generic[0].Next.ToTypeDefOrRef();

                _initializedDataCreator.AddInitializeArrayCode(block, callResult.callStartIndex, num, sig,
                    callResult.returnValue as byte[]);
                RemoveUnboxInstruction(block, callResult.callStartIndex + 1, sig.ToString()); //TODO: sig.ToString() ??
                Logger.v("Decrypted array <{1}>: {0}", callResult.returnValue, sig.ToString());
            }
        }
    }
}