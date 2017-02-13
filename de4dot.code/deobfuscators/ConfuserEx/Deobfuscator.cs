/*
    Copyright (C) 2011-2017 TheProxy

    This file is part of modified de4dot.

    de4dot is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    de4dot is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with de4dot.  If not, see <http://www.gnu.org/licenses/>.
*/

using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System.Collections.Generic;

namespace de4dot.code.deobfuscators.ConfuserEx
{

    public class DeobfuscatorInfo : DeobfuscatorInfoBase
    {
        public const string THE_NAME = "ConfuserEx";
        public const string THE_TYPE = "cx";
        const string DEFAULT_REGEX = DeobfuscatorBase.DEFAULT_ASIAN_VALID_NAME_REGEX;

        public DeobfuscatorInfo()
            : base(DEFAULT_REGEX)
        {
        }

        public override string Name
        {
            get { return THE_NAME; }
        }

        public override string Type
        {
            get { return THE_TYPE; }
        }

        public override IDeobfuscator CreateDeobfuscator()
        {
            return new Deobfuscator(new Deobfuscator.Options
            {
                RenameResourcesInCode = false,
                ValidNameRegex = validNameRegex.Get(),
            });
        }

        class Deobfuscator : DeobfuscatorBase
        {

            bool detectedConfuserExAttribute = false, deobfuscating = false;
            string version = "";
            LzmaFinder lzmaFinder;
            ConstantsDecrypter constantDecrypter;
            ResourceDecrypter resourceDecrypter;

            #region ConstantInliners

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

            #endregion

            internal class Options : OptionsBase
            {
            }

            public override string Type
            {
                get { return DeobfuscatorInfo.THE_TYPE; }
            }

            public override string TypeLong
            {
                get { return DeobfuscatorInfo.THE_NAME; }
            }

            public override string Name
            {
                get { return $"{TypeLong} {version}"; }
            }

            public Deobfuscator(Options options)
                : base(options)
            {
            }

            protected override int DetectInternal()
            {
                int val = 0;
                if (detectedConfuserExAttribute) val += 0;
                if (lzmaFinder.FoundLzma) val += 10;
                if (constantDecrypter.Detected) val += 10;
                if (resourceDecrypter.Detected) val += 10;
                return val;
            }

            protected override void ScanForObfuscator()
            {
                lzmaFinder = new LzmaFinder(module, DeobfuscatedFile);
                lzmaFinder.Find();
                constantDecrypter = new ConstantsDecrypter(module, lzmaFinder.Method, DeobfuscatedFile);
                resourceDecrypter = new ResourceDecrypter(module, lzmaFinder.Method, DeobfuscatedFile);
                if (lzmaFinder.FoundLzma)
                {
                    constantDecrypter.Find();
                    resourceDecrypter.Find();
                }
                DetectConfuserExAttribute();
            }

            public void DetectConfuserExAttribute()
            {
                var versions = new List<string>();
                foreach (var attribute in module.CustomAttributes)
                {
                    if (attribute.TypeFullName != "ConfusedByAttribute")
                        continue;
                    foreach (var argument in attribute.ConstructorArguments)
                    {
                        if (argument.Type.ElementType != ElementType.String)
                            continue;
                        var value = argument.Value.ToString();
                        if (!value.Contains("ConfuserEx"))
                            continue;
                        detectedConfuserExAttribute = true;
                        version = value.Replace("ConfuserEx", "");
                        return;
                    }
                }
            }

            public override void DeobfuscateBegin()
            {
                if (constantDecrypter.Detected)
                {
                    sbyteValueInliner = new SByteValueInliner();
                    byteValueInliner = new ByteValueInliner();
                    int16ValueInliner = new Int16ValueInliner();
                    uint16ValueInliner = new UInt16ValueInliner();
                    int32ValueInliner = new Int32ValueInliner();
                    uint32ValueInliner = new UInt32ValueInliner();
                    int64ValueInliner = new Int64ValueInliner();
                    uint64ValueInliner = new UInt64ValueInliner();
                    singleValueInliner = new SingleValueInliner();
                    doubleValueInliner = new DoubleValueInliner();
                    arrayValueInliner = new ArrayValueInliner(initializedDataCreator);
                    foreach (var info in constantDecrypter.Decrypters)
                    {
                        staticStringInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptString(info, gim, (uint) args[0]));
                        sbyteValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptSByte(info, gim, (uint) args[0]));
                        byteValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptByte(info, gim, (uint) args[0]));
                        int16ValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptInt16(info, gim, (uint) args[0]));
                        uint16ValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptUInt16(info, gim, (uint) args[0]));
                        int32ValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptInt32(info, gim, (uint) args[0]));
                        uint32ValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptUInt32(info, gim, (uint) args[0]));
                        int64ValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptInt64(info, gim, (uint) args[0]));
                        uint64ValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptUInt64(info, gim, (uint) args[0]));
                        singleValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptSingle(info, gim, (uint) args[0]));
                        doubleValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptDouble(info, gim, (uint) args[0]));
                        arrayValueInliner.Add(info.Method,
                            (method, gim, args) => constantDecrypter.DecryptArray(info, gim, (uint) args[0]));
                    }
                    deobfuscating = true;
                }
                if (resourceDecrypter.Detected)
                    resourceDecrypter.Fix();
                base.DeobfuscateBegin();
            }

            public override IEnumerable<IBlocksDeobfuscator> BlocksDeobfuscators
            {
                get
                {
                    var list = new List<IBlocksDeobfuscator>();
                    list.Add(new ControlFlowSolver());

                    if (deobfuscating && int32ValueInliner != null)
                        list.Add(new ConstantsInliner(sbyteValueInliner, byteValueInliner, int16ValueInliner,
                                uint16ValueInliner,
                                int32ValueInliner, uint32ValueInliner, int64ValueInliner, uint64ValueInliner,
                                singleValueInliner, doubleValueInliner, arrayValueInliner)
                            {ExecuteIfNotModified = true});
                    return list;
                }
            }

            bool CanRemoveLzma = true;

            public override void DeobfuscateEnd()
            {
                FindAndRemoveInlinedMethods();

                List<MethodDef> toRemoveFromCctor = new List<MethodDef>();

                if (constantDecrypter.Detected)
                    if (CanRemoveStringDecrypterType)
                    {
                        toRemoveFromCctor.Add(constantDecrypter.Method);
                        AddMethodToBeRemoved(constantDecrypter.Method, "Constant Decrypter Initializer");
                        foreach (var dec in constantDecrypter.Decrypters)
                            AddMethodToBeRemoved(dec.Method, "Constant Decrypter Method");
                        AddFieldsToBeRemoved(constantDecrypter.Fields, "Constant Decrypter Fields");
                        AddTypeToBeRemoved(constantDecrypter.Type, "Array field signature type");
                    }
                    else
                        CanRemoveLzma = false;

                if (resourceDecrypter.Detected && resourceDecrypter.CanRemoveLzma)
                {
                    toRemoveFromCctor.Add(resourceDecrypter.Method);
                    AddMethodToBeRemoved(resourceDecrypter.Method, "Resource decrypter Initializer method");
                    AddMethodToBeRemoved(resourceDecrypter.AssembyResolveMethod,
                        "Resource decrypter AssemblyResolve method");
                    AddFieldsToBeRemoved(resourceDecrypter.Fields, "Constant Decrypter Fields");
                    AddTypeToBeRemoved(resourceDecrypter.Type, "Array field signature type");
                }

                if (!constantDecrypter.CanRemoveLzma || !resourceDecrypter.CanRemoveLzma)
                    CanRemoveLzma = false;

                if (lzmaFinder.FoundLzma && CanRemoveLzma)
                {
                    AddMethodToBeRemoved(lzmaFinder.Method, "Lzma Decompress method");
                    AddTypesToBeRemoved(lzmaFinder.Types, "Lzma Nested Types");
                }

                var moduleCctor = DotNetUtils.GetModuleTypeCctor(module);
                foreach (var instr in moduleCctor.Body.Instructions)
                    if (instr.OpCode == OpCodes.Call && instr.Operand is MethodDef &&
                        toRemoveFromCctor.Contains(instr.Operand as MethodDef))
                        instr.OpCode = OpCodes.Nop;

                //No more mixed!
                module.IsILOnly = true;

                base.DeobfuscateEnd();
            }

            public override IEnumerable<int> GetStringDecrypterMethods()
            {
                var list = new List<int>();
                return list;
            }
        }
    }
}