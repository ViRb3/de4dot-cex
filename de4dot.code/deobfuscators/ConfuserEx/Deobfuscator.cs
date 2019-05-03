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

using System.Collections.Generic;
using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace de4dot.code.deobfuscators.ConfuserEx
{
    public class DeobfuscatorInfo : DeobfuscatorInfoBase
    {
        internal const string THE_NAME = "ConfuserEx";
        public const string THE_TYPE = "crx";
        private const string DEFAULT_REGEX = DeobfuscatorBase.DEFAULT_ASIAN_VALID_NAME_REGEX;

        public DeobfuscatorInfo()
            : base(DEFAULT_REGEX)
        {
        }

        public override string Name => THE_NAME;
        public override string Type => THE_TYPE;

        public override IDeobfuscator CreateDeobfuscator()
        {
            return new Deobfuscator(new Deobfuscator.Options
            {
                RenameResourcesInCode = false,
                ValidNameRegex = validNameRegex.Get()
            });
        }

        private class Deobfuscator : DeobfuscatorBase
        {
            private readonly ControlFlowFixer _controlFlowFixer = new ControlFlowFixer();

            private bool _canRemoveLzma = true;
            private ConstantsDecrypter _constantDecrypter;
            private bool _detectedConfuserExAttribute, _deobfuscating;
            private LzmaFinder _lzmaFinder;
            private ProxyCallFixer _proxyCallFixer;
            private ResourceDecrypter _resourceDecrypter;
            private string _version = "";

            public Deobfuscator(Options options)
                : base(options)
            {
            }

            public override string Type => THE_TYPE;
            public override string TypeLong => THE_NAME;
            public override string Name => $"{TypeLong} {_version}";

            public override IEnumerable<IBlocksDeobfuscator> BlocksDeobfuscators
            {
                get
                {
                    var list = new List<IBlocksDeobfuscator>();
                    list.Add(_controlFlowFixer);

                    if (_deobfuscating && _int32ValueInliner != null)
                    {
                        var constantInliner = new ConstantsInliner(_sbyteValueInliner, _byteValueInliner,
                            _int16ValueInliner,
                            _uint16ValueInliner, _int32ValueInliner, _uint32ValueInliner, _int64ValueInliner,
                            _uint64ValueInliner, _singleValueInliner, _doubleValueInliner, _arrayValueInliner)
                        {
                            ExecuteIfNotModified = true
                        };
                        list.Add(constantInliner);
                    }
                    return list;
                }
            }

            protected override int DetectInternal()
            {
                var val = 0;
                if (_detectedConfuserExAttribute) val += 2;
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
                        _version = value.Replace("ConfuserEx", "").Trim();
                        return;
                    }
                }
            }

            public override void DeobfuscateBegin()
            {
                if (_constantDecrypter.Detected)
                {
                    _sbyteValueInliner = new SByteValueInliner();
                    _byteValueInliner = new ByteValueInliner();
                    _int16ValueInliner = new Int16ValueInliner();
                    _uint16ValueInliner = new UInt16ValueInliner();
                    _int32ValueInliner = new Int32ValueInliner();
                    _uint32ValueInliner = new UInt32ValueInliner();
                    _int64ValueInliner = new Int64ValueInliner();
                    _uint64ValueInliner = new UInt64ValueInliner();
                    _singleValueInliner = new SingleValueInliner();
                    _doubleValueInliner = new DoubleValueInliner();
                    _arrayValueInliner = new ArrayValueInliner(initializedDataCreator);
                    foreach (var info in _constantDecrypter.Decrypters)
                    {
                        staticStringInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptString(info, gim, (uint) args[0]));
                        _sbyteValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptSByte(info, gim, (uint) args[0]));
                        _byteValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptByte(info, gim, (uint) args[0]));
                        _int16ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptInt16(info, gim, (uint) args[0]));
                        _uint16ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptUInt16(info, gim, (uint) args[0]));
                        _int32ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptInt32(info, gim, (uint) args[0]));
                        _uint32ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptUInt32(info, gim, (uint) args[0]));
                        _int64ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptInt64(info, gim, (uint) args[0]));
                        _uint64ValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptUInt64(info, gim, (uint) args[0]));
                        _singleValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptSingle(info, gim, (uint) args[0]));
                        _doubleValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptDouble(info, gim, (uint) args[0]));
                        _arrayValueInliner.Add(info.Method,
                            (method, gim, args) => _constantDecrypter.DecryptArray(info, gim, (uint) args[0]));
                    }
                    _deobfuscating = true;
                }
                if (_resourceDecrypter.Detected)
                {
                    _resourceDecrypter.Fix();
                }

                base.DeobfuscateBegin();
            }

            public override void DeobfuscateEnd()
            {
                FindAndRemoveInlinedMethods();

                var toRemoveFromCctor = new List<MethodDef>();

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
                    {
                        _canRemoveLzma = false;
                    }

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
                {
                    _canRemoveLzma = false;
                }

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
                if (moduleCctor != null)
                    foreach (var instr in moduleCctor.Body.Instructions)
                        if (instr.OpCode == OpCodes.Call && instr.Operand is MethodDef
                            && toRemoveFromCctor.Contains((MethodDef) instr.Operand))
                            instr.OpCode = OpCodes.Nop;

                //TODO: Might not always be correct
                //No more mixed!
                module.IsILOnly = true;

                base.DeobfuscateEnd();
            }

            public override IEnumerable<int> GetStringDecrypterMethods()
            {
                return new List<int>();
            }

            public override void DeobfuscateMethodEnd(Blocks blocks)
            {
                _proxyCallFixer.Deobfuscate(blocks);
                base.DeobfuscateMethodEnd(blocks);
            }

            internal class Options : OptionsBase
            {
            }

            #region ConstantInliners

            private SByteValueInliner _sbyteValueInliner;
            private ByteValueInliner _byteValueInliner;
            private Int16ValueInliner _int16ValueInliner;
            private UInt16ValueInliner _uint16ValueInliner;
            private Int32ValueInliner _int32ValueInliner;
            private UInt32ValueInliner _uint32ValueInliner;
            private Int64ValueInliner _int64ValueInliner;
            private UInt64ValueInliner _uint64ValueInliner;
            private SingleValueInliner _singleValueInliner;
            private DoubleValueInliner _doubleValueInliner;
            private ArrayValueInliner _arrayValueInliner;

            #endregion
        }
    }
}