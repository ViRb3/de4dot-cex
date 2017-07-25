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
            private bool _detectedConfuserExAttribute = false, _deobfuscating = false;
            private string _version = "";
            private LzmaFinder _lzmaFinder;
            private ConstantsDecrypter _constantDecrypter;
            private ResourceDecrypter _resourceDecrypter;
            private ProxyCallFixer _proxyCallFixer;
            private ControlFlowFixer _controlFlowFixer = new ControlFlowFixer();

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
                get { return $"{TypeLong} {_version}"; }
            }

            public Deobfuscator(Options options)
                : base(options)
            {
            }

            protected override int DetectInternal()
            {
                int val = 0;
                if (_detectedConfuserExAttribute) val += 0;
                if (_lzmaFinder.FoundLzma) val += 10;
                if (_constantDecrypter.Detected) val += 10;
                if (_resourceDecrypter.Detected) val += 10;
                return val;
            }

            protected override void ScanForObfuscator()
            {
                _lzmaFinder = new LzmaFinder(module, DeobfuscatedFile);
                _lzmaFinder.Find();
                _constantDecrypter = new ConstantsDecrypter(module, _lzmaFinder.Method, DeobfuscatedFile);
                _resourceDecrypter = new ResourceDecrypter(module, _lzmaFinder.Method, DeobfuscatedFile);
                if (_lzmaFinder.FoundLzma)
                {
                    _constantDecrypter.Find();
                    _resourceDecrypter.Find();
                }

                _proxyCallFixer = new ProxyCallFixer(module, DeobfuscatedFile);
                _proxyCallFixer.FindDelegateCreatorMethod();
                _proxyCallFixer.Find();

                DetectConfuserExAttribute();
            }

            private void DetectConfuserExAttribute()
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
                        _detectedConfuserExAttribute = true;
                        _version = value.Replace("ConfuserEx", "");
                        return;
                    }
                }
            }

            public override void DeobfuscateBegin()
            {
                if (_constantDecrypter.Detected)
                {
                    Logger.w("Constants encryption detected! Please note that the decryption method has to be set manually!"); //TODO: Remove

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
                    foreach (var info in _constantDecrypter.Decrypters)
                    {
                        staticStringInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptString(info, gim, (uint) args[0]));
                        sbyteValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptSByte(info, gim, (uint) args[0]));
                        byteValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptByte(info, gim, (uint) args[0]));
                        int16ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptInt16(info, gim, (uint) args[0]));
                        uint16ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptUInt16(info, gim, (uint) args[0]));
                        int32ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptInt32(info, gim, (uint) args[0]));
                        uint32ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptUInt32(info, gim, (uint) args[0]));
                        int64ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptInt64(info, gim, (uint) args[0]));
                        uint64ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptUInt64(info, gim, (uint) args[0]));
                        singleValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptSingle(info, gim, (uint) args[0]));
                        doubleValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptDouble(info, gim, (uint) args[0]));
                        arrayValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptArray(info, gim, (uint) args[0]));
                    }
                    _deobfuscating = true;
                }
                if (_resourceDecrypter.Detected)
                {
                    Logger.w("Resource encryption detected! Please note that the decryption method has to be set manually!"); //TODO: Remove
                    _resourceDecrypter.Fix();
                }

                base.DeobfuscateBegin();
            }

            public override IEnumerable<IBlocksDeobfuscator> BlocksDeobfuscators
            {
                get
                {
                    var list = new List<IBlocksDeobfuscator>();
                    list.Add(_controlFlowFixer);

                    if (_deobfuscating && int32ValueInliner != null)
                        list.Add(new ConstantsInliner(sbyteValueInliner, byteValueInliner, int16ValueInliner,
                                uint16ValueInliner,
                                int32ValueInliner, uint32ValueInliner, int64ValueInliner, uint64ValueInliner,
                                singleValueInliner, doubleValueInliner, arrayValueInliner)
                            {ExecuteIfNotModified = true});
                    return list;
                }
            }

            bool _canRemoveLzma = true;

            public override void DeobfuscateEnd()
            {
                FindAndRemoveInlinedMethods();

                List<MethodDef> toRemoveFromCctor = new List<MethodDef>();

                if (_constantDecrypter.Detected)
                    if (CanRemoveStringDecrypterType)
                    {
                        toRemoveFromCctor.Add(_constantDecrypter.Method);
                        AddMethodToBeRemoved(_constantDecrypter.Method, "Constant Decrypter Initializer");
                        foreach (var dec in _constantDecrypter.Decrypters)
                            AddMethodToBeRemoved(dec.Method, "Constant Decrypter Method");
                        AddFieldsToBeRemoved(_constantDecrypter.Fields, "Constant Decrypter Fields");
                        AddTypeToBeRemoved(_constantDecrypter.Type, "Array field signature type");
                    }
                    else
                        _canRemoveLzma = false;

                if (_resourceDecrypter.Detected && _resourceDecrypter.CanRemoveLzma)
                {
                    toRemoveFromCctor.Add(_resourceDecrypter.Method);
                    AddMethodToBeRemoved(_resourceDecrypter.Method, "Resource decrypter Initializer method");
                    AddMethodToBeRemoved(_resourceDecrypter.AssembyResolveMethod,
                        "Resource decrypter AssemblyResolve method");
                    AddFieldsToBeRemoved(_resourceDecrypter.Fields, "Constant Decrypter Fields");
                    AddTypeToBeRemoved(_resourceDecrypter.Type, "Array field signature type");
                }

                if (!_constantDecrypter.CanRemoveLzma || !_resourceDecrypter.CanRemoveLzma)
                    _canRemoveLzma = false;

                if (_lzmaFinder.FoundLzma && _canRemoveLzma)
                {
                    AddMethodToBeRemoved(_lzmaFinder.Method, "Lzma Decompress method");
                    AddTypesToBeRemoved(_lzmaFinder.Types, "Lzma Nested Types");
                }

                if (_proxyCallFixer.Detected)
                {
                    AddTypesToBeRemoved(_proxyCallFixer.DelegateTypes, "Proxy delegates");
                    AddMethodsToBeRemoved(_proxyCallFixer.DelegateCreatorMethods, "Proxy creator methods");
                    AddTypesToBeRemoved(_proxyCallFixer.AttributeTypes, "Proxy creator attributes");
                    AddMethodsToBeRemoved(_proxyCallFixer.NativeMethods, "Proxy native methods");
                }
                
                AddMethodsToBeRemoved(_controlFlowFixer.NativeMethods, "Control flow native methods");

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

            public override void DeobfuscateMethodEnd(Blocks blocks)
            {
                _proxyCallFixer.Deobfuscate(blocks);
                base.DeobfuscateMethodEnd(blocks);
            }
        }
    }
}