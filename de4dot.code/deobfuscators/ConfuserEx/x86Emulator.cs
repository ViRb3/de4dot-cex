﻿using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.IO;

namespace de4dot.code.deobfuscators.ConfuserEx
{
	public class x86Emulator : IDisposable {

        static readonly byte[] prolog2 = new byte[] {
            0x89, 0xE0, 0x53, 0x57, 0x56, 0x29, 0xe0,
            0x83, 0xf8, 0x18, 0x74, 0x07, 0x8b, 0x44,
            0x24, 0x10, 0x50, 0xeb, 0x01, 0x51
        };
		static readonly byte[] epilog2 = new byte[] {
			0x5E, 0x5F, 0x5B, 0xC3,
		};

		MyPEImage peImage;
		IBinaryReader reader;
		uint[] args;
		int nextArgIndex;
		uint[] regs = new uint[8];
		byte modRM, mod, reg, rm;
		enum OpCode {
			Add_RI,
			Add_RR,
			Mov_RI,
			Mov_RR,
            IMul_RI,
            IMul_RR,
            Neg_R,
			Not_R,
			Pop_R,
			Sub_RI,
			Sub_RR,
			Xor_RI,
			Xor_RR,
		}
		interface IOperand {}
		class RegOperand : IOperand {
            static readonly string[] names = new string[8] { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", };
			public readonly int reg;
            public RegOperand(int reg) { this.reg = reg; }
            public override string ToString() { return names[reg]; }
		}

		class ImmOperand : IOperand {
			public readonly int imm;

			public ImmOperand(int imm) {
				this.imm = imm;
			}

			public override string ToString() {
				return string.Format("{0:X2}h", imm);
			}
		}

		class Instruction {
			public readonly OpCode opCode;
			public IOperand op1;
			public IOperand op2;

            public Instruction(OpCode opCode) : this(opCode, null, null) { }
            public Instruction(OpCode opCode, IOperand op1) : this(opCode, op1, null) { }

			public Instruction(OpCode opCode, IOperand op1, IOperand op2) {
				this.opCode = opCode;
				this.op1 = op1;
				this.op2 = op2;
			}

			public override string ToString() {
				if (op1 != null && op2 != null)
					return string.Format("{0} {1},{2}", opCode, op1, op2);
				if (op1 != null)
					return string.Format("{0} {1}", opCode, op1);
				return string.Format("{0}", opCode);
			}
		}

		public x86Emulator(byte[] fileData) {
			peImage = new MyPEImage(fileData);
			reader = peImage.Reader;
		}

        public uint Emulate(MethodDef method, int arg)
        {
            return Emulate((uint)method.RVA, new uint[] { (uint)arg });
        }

        public uint Emulate(uint rva, uint arg) {
			return Emulate(rva, new uint[] { arg });
		}

		public uint Emulate(uint rva, uint[] args) {
			Initialize(args);
			reader.Position = peImage.RvaToOffset(rva);
			byte[] prolog, epilog;
			if (IsBytes(prolog2)) {
				prolog = prolog2;
				epilog = epilog2;
			}else
				throw new ApplicationException(string.Format("Missing prolog @ RVA {0:X8}", rva));
            reader.Position += prolog.Length;
			while (!IsBytes(epilog))
				Emulate();

			return regs[0];
		}

		void Initialize(uint[] args) {
			this.args = args;
			nextArgIndex = 0;
			for (int i = 0; i < regs.Length; i++)
				regs[i] = 0;
		}

		bool IsBytes(IList<byte> bytes) {
			long oldPos = reader.Position;
			bool result = true;
			for (int i = 0; i < bytes.Count; i++) {
				if (bytes[i] != reader.ReadByte()) {
					result = false;
					break;
				}
			}
			reader.Position = oldPos;
			return result;
		}

		void Emulate() {
			var instr = Decode();
            switch (instr.opCode)
            {
                case OpCode.Add_RI:
                case OpCode.Add_RR:
                    WriteReg(instr.op1, ReadOp(instr.op1) + ReadOp(instr.op2));
                    break;

                case OpCode.Mov_RI:
                case OpCode.Mov_RR:
                    WriteReg(instr.op1, ReadOp(instr.op2));
                    break;
                case OpCode.IMul_RI:
                case OpCode.IMul_RR:
                    WriteReg(instr.op1, ReadOp(instr.op1) * ReadOp(instr.op2));
                    break;
                case OpCode.Neg_R:
                    WriteReg(instr.op1, (uint)-(int)ReadOp(instr.op1));
                    break;

                case OpCode.Not_R:
                    WriteReg(instr.op1, ~ReadOp(instr.op1));
                    break;

                case OpCode.Pop_R:
                    WriteReg(instr.op1, GetNextArg());
                    break;

                case OpCode.Sub_RI:
                case OpCode.Sub_RR:
                    WriteReg(instr.op1, ReadOp(instr.op1) - ReadOp(instr.op2));
                    break;

                case OpCode.Xor_RI:
                case OpCode.Xor_RR:
                    WriteReg(instr.op1, ReadOp(instr.op1) ^ ReadOp(instr.op2));
                    break;

                default: throw new NotSupportedException();
            }
		}

		uint GetNextArg() {
			if (nextArgIndex >= args.Length)
				throw new ApplicationException("No more args");
			return args[nextArgIndex++];
		}

		void WriteReg(IOperand op, uint val) {
            regs[((RegOperand)op).reg] = val;
		}

		uint ReadOp(IOperand op) {
            if (op is RegOperand regOp)
                return regs[regOp.reg];
            if (op is ImmOperand immOp)
                return (uint)immOp.imm;
            throw new NotSupportedException();
		}

        Instruction Decode()
        {
            byte opc = reader.ReadByte();
            switch (opc)
            {
                case 0x01:  // ADD Ed,Gd
                    ParseModRM();
                    return new Instruction(OpCode.Add_RR, new RegOperand(rm), new RegOperand(reg));

                case 0x0F: // IMUL Ed,Gd
                    ParseModRM();
                    return new Instruction(OpCode.IMul_RR, new RegOperand(rm), new RegOperand(reg));

                case 0x29:  // SUB Ed,Gd
                    ParseModRM();
                    return new Instruction(OpCode.Sub_RR, new RegOperand(rm), new RegOperand(reg));

                case 0x31:  // XOR Ed,Gd
                    ParseModRM();
                    return new Instruction(OpCode.Xor_RR, new RegOperand(rm), new RegOperand(reg));

                case 0x58:  // POP EAX
                case 0x59:  // POP ECX
                case 0x5A:  // POP EDX
                case 0x5B:  // POP EBX
                case 0x5C:  // POP ESP
                case 0x5D:  // POP EBP
                case 0x5E:  // POP ESI
                case 0x5F:  // POP EDI
                    return new Instruction(OpCode.Pop_R, new RegOperand(opc - 0x58));

                case 0x69:  // Imul Ed, Id
                    ParseModRM();
                    return new Instruction(OpCode.IMul_RI, new RegOperand(rm), new ImmOperand(reader.ReadInt32()));

                case 0x81:  // Grp1 Ed,Id
                    ParseModRM();
                    switch (reg)
                    {
                        case 0: return new Instruction(OpCode.Add_RI, new RegOperand(rm), new ImmOperand(reader.ReadInt32()));
                        case 5: return new Instruction(OpCode.Sub_RI, new RegOperand(rm), new ImmOperand(reader.ReadInt32()));
                        case 6: return new Instruction(OpCode.Xor_RI, new RegOperand(rm), new ImmOperand(reader.ReadInt32()));
                        default: throw new NotSupportedException();
                    }

                case 0x89:  // MOV Ed,Gd
                    ParseModRM();
                    return new Instruction(OpCode.Mov_RR, new RegOperand(rm), new RegOperand(reg));

                case 0xB8:  // MOV EAX,Id
                case 0xB9:  // MOV ECX,Id
                case 0xBA:  // MOV EDX,Id
                case 0xBB:  // MOV EBX,Id
                case 0xBC:  // MOV ESP,Id
                case 0xBD:  // MOV EBP,Id
                case 0xBE:  // MOV ESI,Id
                case 0xBF:  // MOV EDI,Id
                    return new Instruction(OpCode.Mov_RI, new RegOperand(opc - 0xB8), new ImmOperand(reader.ReadInt32()));

                case 0xF7:  // Grp3 Ev
                    ParseModRM();
                    switch (reg)
                    {
                        case 2: return new Instruction(OpCode.Not_R, new RegOperand(rm));
                        case 3: return new Instruction(OpCode.Neg_R, new RegOperand(rm));
                        default: throw new NotSupportedException();
                    }

                default: throw new NotSupportedException(string.Format("Invalid opcode: {0:X2}", opc));
            }
        }

		void ParseModRM() {
			modRM = reader.ReadByte();
			mod = (byte)((modRM >> 6) & 7);
			reg = (byte)((modRM >> 3) & 7);
			rm = (byte)(modRM & 7);
			if (mod != 3)
				throw new ApplicationException("Memory operand");
		}

		public void Dispose() {
			if (peImage != null)
				peImage.Dispose();
			peImage = null;
			reader = null;
		}
	}
}
