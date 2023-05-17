#include "z3/z3states.hpp"
#include "z3/z3ASMx64Instructions.hpp"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <z3++.h>

#include <iostream>

namespace Z3SystemTranslateFuncs {

	static inline z3::expr** get_val_expr(z3::context& z3c, x8664_ctx& state, ZydisDecodedOperand op)
	{
		if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			z3::expr** ret;

			switch (op.reg.value)
			{
			case ZYDIS_REGISTER_RAX: return ret = &state.rax;
			case ZYDIS_REGISTER_EAX: return ret = &state.rax;
			case ZYDIS_REGISTER_AX: return ret = &state.rax;
			case ZYDIS_REGISTER_AH: return ret = &state.rax;
			case ZYDIS_REGISTER_AL: return ret = &state.rax;

			case ZYDIS_REGISTER_RBX: return ret = &state.rbx;
			case ZYDIS_REGISTER_EBX: return ret = &state.rbx;
			case ZYDIS_REGISTER_BX: return ret = &state.rbx;
			case ZYDIS_REGISTER_BH: return ret = &state.rbx;
			case ZYDIS_REGISTER_BL: return ret = &state.rbx;

			case ZYDIS_REGISTER_RCX: return ret = &state.rcx;
			case ZYDIS_REGISTER_ECX: return ret = &state.rcx;
			case ZYDIS_REGISTER_CX: return ret = &state.rcx;
			case ZYDIS_REGISTER_CH: return ret = &state.rcx;
			case ZYDIS_REGISTER_CL: return ret = &state.rcx;

			case ZYDIS_REGISTER_RDX: return ret = &state.rdx;
			case ZYDIS_REGISTER_EDX: return ret = &state.rdx;
			case ZYDIS_REGISTER_DX: return ret = &state.rdx;
			case ZYDIS_REGISTER_DH: return ret = &state.rdx;
			case ZYDIS_REGISTER_DL: return ret = &state.rdx;

			case ZYDIS_REGISTER_RBP: return ret = &state.rbp;
			case ZYDIS_REGISTER_EBP: return ret = &state.rbp;
			case ZYDIS_REGISTER_BP: return ret = &state.rbp;
			case ZYDIS_REGISTER_BPL: return ret = &state.rbp;

			case ZYDIS_REGISTER_RSP: return ret = &state.rsp;
			case ZYDIS_REGISTER_ESP: return ret = &state.rsp;
			case ZYDIS_REGISTER_SP: return ret = &state.rsp;
			case ZYDIS_REGISTER_SPL: return ret = &state.rsp;

			case ZYDIS_REGISTER_RSI: return ret = &state.rsi;
			case ZYDIS_REGISTER_ESI: return ret = &state.rsi;
			case ZYDIS_REGISTER_SI: return ret = &state.rsi;
			case ZYDIS_REGISTER_SIL: return ret = &state.rsi;

			case ZYDIS_REGISTER_RDI: return ret = &state.rdi;
			case ZYDIS_REGISTER_EDI: return ret = &state.rdi;
			case ZYDIS_REGISTER_DI: return ret = &state.rdi;
			case ZYDIS_REGISTER_DIL: return ret = &state.rdi;

			case ZYDIS_REGISTER_R8: return ret = &state.r8;
			case ZYDIS_REGISTER_R8D: return ret = &state.r8;
			case ZYDIS_REGISTER_R8W: return ret = &state.r8;
			case ZYDIS_REGISTER_R8B: return ret = &state.r8;

			case ZYDIS_REGISTER_R9: return ret = &state.r9;
			case ZYDIS_REGISTER_R9D: return ret = &state.r9;
			case ZYDIS_REGISTER_R9W: return ret = &state.r9;
			case ZYDIS_REGISTER_R9B: return ret = &state.r9;

			case ZYDIS_REGISTER_R10: return ret = &state.r10;
			case ZYDIS_REGISTER_R10D: return ret = &state.r10;
			case ZYDIS_REGISTER_R10W: return ret = &state.r10;
			case ZYDIS_REGISTER_R10B: return ret = &state.r10;

			case ZYDIS_REGISTER_R11: return ret = &state.r11;
			case ZYDIS_REGISTER_R11D: return ret = &state.r11;
			case ZYDIS_REGISTER_R11W: return ret = &state.r11;
			case ZYDIS_REGISTER_R11B: return ret = &state.r11;

			case ZYDIS_REGISTER_R12: return ret = &state.r12;
			case ZYDIS_REGISTER_R12D: return ret = &state.r12;
			case ZYDIS_REGISTER_R12W: return ret = &state.r12;
			case ZYDIS_REGISTER_R12B: return ret = &state.r12;

			case ZYDIS_REGISTER_R13: return ret = &state.r13;
			case ZYDIS_REGISTER_R13D: return ret = &state.r13;
			case ZYDIS_REGISTER_R13W: return ret = &state.r13;
			case ZYDIS_REGISTER_R13B: return ret = &state.r13;

			case ZYDIS_REGISTER_R14: return ret = &state.r14;
			case ZYDIS_REGISTER_R14D: return ret = &state.r14;
			case ZYDIS_REGISTER_R14W: return ret = &state.r14;
			case ZYDIS_REGISTER_R14B: return ret = &state.r14;

			case ZYDIS_REGISTER_R15: return ret = &state.r15;
			case ZYDIS_REGISTER_R15D: return ret = &state.r15;
			case ZYDIS_REGISTER_R15W: return ret = &state.r15;
			case ZYDIS_REGISTER_R15B: return ret = &state.r15;

			case ZYDIS_REGISTER_RFLAGS: return ret = &state.rflags;

			default:
				throw std::exception("bad register");
			}
		}
		else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			state.immediate.push_back(new z3::expr(z3c.bv_val(static_cast<uint64_t>(op.imm.value.u), 64)));

			return &state.immediate.back();
		}
		else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			z3::expr** ret;

			switch (op.mem.base)
			{
			case ZYDIS_REGISTER_RAX: ret = &state.rax; break;
			case ZYDIS_REGISTER_EAX: ret = &state.rax; break;
			case ZYDIS_REGISTER_AX: ret = &state.rax; break;
			case ZYDIS_REGISTER_AH: ret = &state.rax; break;
			case ZYDIS_REGISTER_AL: ret = &state.rax; break;

			case ZYDIS_REGISTER_RBX: ret = &state.rbx; break;
			case ZYDIS_REGISTER_EBX: ret = &state.rbx; break;
			case ZYDIS_REGISTER_BX: ret = &state.rbx; break;
			case ZYDIS_REGISTER_BH: ret = &state.rbx; break;
			case ZYDIS_REGISTER_BL: ret = &state.rbx; break;

			case ZYDIS_REGISTER_RCX: ret = &state.rcx; break;
			case ZYDIS_REGISTER_ECX: ret = &state.rcx; break;
			case ZYDIS_REGISTER_CX: ret = &state.rcx; break;
			case ZYDIS_REGISTER_CH: ret = &state.rcx; break;
			case ZYDIS_REGISTER_CL: ret = &state.rcx; break;

			case ZYDIS_REGISTER_RDX: ret = &state.rdx; break;
			case ZYDIS_REGISTER_EDX: ret = &state.rdx; break;
			case ZYDIS_REGISTER_DX: ret = &state.rdx; break;
			case ZYDIS_REGISTER_DH: ret = &state.rdx; break;
			case ZYDIS_REGISTER_DL: ret = &state.rdx; break;

			case ZYDIS_REGISTER_RBP: ret = &state.rbp; break;
			case ZYDIS_REGISTER_EBP: ret = &state.rbp; break;
			case ZYDIS_REGISTER_BP: ret = &state.rbp; break;
			case ZYDIS_REGISTER_BPL: ret = &state.rbp; break;

			case ZYDIS_REGISTER_RSP: ret = &state.rsp; break;
			case ZYDIS_REGISTER_ESP: ret = &state.rsp; break;
			case ZYDIS_REGISTER_SP: ret = &state.rsp; break;
			case ZYDIS_REGISTER_SPL: ret = &state.rsp; break;

			case ZYDIS_REGISTER_RSI: ret = &state.rsi; break;
			case ZYDIS_REGISTER_ESI: ret = &state.rsi; break;
			case ZYDIS_REGISTER_SI: ret = &state.rsi; break;
			case ZYDIS_REGISTER_SIL: ret = &state.rsi; break;

			case ZYDIS_REGISTER_RDI: ret = &state.rdi; break;
			case ZYDIS_REGISTER_EDI: ret = &state.rdi; break;
			case ZYDIS_REGISTER_DI: ret = &state.rdi; break;
			case ZYDIS_REGISTER_DIL: ret = &state.rdi; break;

			case ZYDIS_REGISTER_R8: ret = &state.r8; break;
			case ZYDIS_REGISTER_R8D: ret = &state.r8; break;
			case ZYDIS_REGISTER_R8W: ret = &state.r8; break;
			case ZYDIS_REGISTER_R8B: ret = &state.r8; break;

			case ZYDIS_REGISTER_R9: ret = &state.r9; break;
			case ZYDIS_REGISTER_R9D: ret = &state.r9; break;
			case ZYDIS_REGISTER_R9W: ret = &state.r9; break;
			case ZYDIS_REGISTER_R9B: ret = &state.r9; break;

			case ZYDIS_REGISTER_R10: ret = &state.r10; break;
			case ZYDIS_REGISTER_R10D: ret = &state.r10; break;
			case ZYDIS_REGISTER_R10W: ret = &state.r10; break;
			case ZYDIS_REGISTER_R10B: ret = &state.r10; break;

			case ZYDIS_REGISTER_R11: ret = &state.r11; break;
			case ZYDIS_REGISTER_R11D: ret = &state.r11; break;
			case ZYDIS_REGISTER_R11W: ret = &state.r11; break;
			case ZYDIS_REGISTER_R11B: ret = &state.r11; break;

			case ZYDIS_REGISTER_R12: ret = &state.r12; break;
			case ZYDIS_REGISTER_R12D: ret = &state.r12; break;
			case ZYDIS_REGISTER_R12W: ret = &state.r12; break;
			case ZYDIS_REGISTER_R12B: ret = &state.r12; break;

			case ZYDIS_REGISTER_R13: ret = &state.r13; break;
			case ZYDIS_REGISTER_R13D: ret = &state.r13; break;
			case ZYDIS_REGISTER_R13W: ret = &state.r13; break;
			case ZYDIS_REGISTER_R13B: ret = &state.r13; break;

			case ZYDIS_REGISTER_R14: ret = &state.r14; break;
			case ZYDIS_REGISTER_R14D: ret = &state.r14; break;
			case ZYDIS_REGISTER_R14W: ret = &state.r14; break;
			case ZYDIS_REGISTER_R14B: ret = &state.r14; break;

			case ZYDIS_REGISTER_R15: ret = &state.r15; break;
			case ZYDIS_REGISTER_R15D: ret = &state.r15; break;
			case ZYDIS_REGISTER_R15W: ret = &state.r15; break;
			case ZYDIS_REGISTER_R15B: ret = &state.r15; break;

			default:
				throw std::exception("bad register");
			}

			if (ret)
			{
				z3::expr* base_expr = *ret;
				z3::expr* index_expr = nullptr;
				z3::expr* disp_expr = nullptr;

				if (op.mem.index != ZYDIS_REGISTER_NONE)
				{
					switch (op.mem.index)
					{
					case ZYDIS_REGISTER_RAX: index_expr = state.rax; break;
					case ZYDIS_REGISTER_EAX: index_expr = state.rax; break;
					case ZYDIS_REGISTER_AX: index_expr = state.rax; break;
					case ZYDIS_REGISTER_AH: index_expr = state.rax; break;
					case ZYDIS_REGISTER_AL: index_expr = state.rax; break;

					case ZYDIS_REGISTER_RBX: index_expr = state.rbx; break;
					case ZYDIS_REGISTER_EBX: index_expr = state.rbx; break;
					case ZYDIS_REGISTER_BX: index_expr = state.rbx; break;
					case ZYDIS_REGISTER_BH: index_expr = state.rbx; break;
					case ZYDIS_REGISTER_BL: index_expr = state.rbx; break;

					case ZYDIS_REGISTER_RCX: index_expr = state.rcx; break;
					case ZYDIS_REGISTER_ECX: index_expr = state.rcx; break;
					case ZYDIS_REGISTER_CX: index_expr = state.rcx; break;
					case ZYDIS_REGISTER_CH: index_expr = state.rcx; break;
					case ZYDIS_REGISTER_CL: index_expr = state.rcx; break;

					case ZYDIS_REGISTER_RDX: index_expr = state.rdx; break;
					case ZYDIS_REGISTER_EDX: index_expr = state.rdx; break;
					case ZYDIS_REGISTER_DX: index_expr = state.rdx; break;
					case ZYDIS_REGISTER_DH: index_expr = state.rdx; break;
					case ZYDIS_REGISTER_DL: index_expr = state.rdx; break;

					case ZYDIS_REGISTER_RBP: index_expr = state.rbp; break;
					case ZYDIS_REGISTER_EBP: index_expr = state.rbp; break;
					case ZYDIS_REGISTER_BP: index_expr = state.rbp; break;
					case ZYDIS_REGISTER_BPL: index_expr = state.rbp; break;

					case ZYDIS_REGISTER_RSP: index_expr = state.rsp; break;
					case ZYDIS_REGISTER_ESP: index_expr = state.rsp; break;
					case ZYDIS_REGISTER_SP: index_expr = state.rsp; break;
					case ZYDIS_REGISTER_SPL: index_expr = state.rsp; break;

					case ZYDIS_REGISTER_RSI: index_expr = state.rsi; break;
					case ZYDIS_REGISTER_ESI: index_expr = state.rsi; break;
					case ZYDIS_REGISTER_SI: index_expr = state.rsi; break;
					case ZYDIS_REGISTER_SIL: index_expr = state.rsi; break;

					case ZYDIS_REGISTER_RDI: index_expr = state.rdi; break;
					case ZYDIS_REGISTER_EDI: index_expr = state.rdi; break;
					case ZYDIS_REGISTER_DI: index_expr = state.rdi; break;
					case ZYDIS_REGISTER_DIL: index_expr = state.rdi; break;

					case ZYDIS_REGISTER_R8: index_expr = state.r8; break;
					case ZYDIS_REGISTER_R8D: index_expr = state.r8; break;
					case ZYDIS_REGISTER_R8W: index_expr = state.r8; break;
					case ZYDIS_REGISTER_R8B: index_expr = state.r8; break;

					case ZYDIS_REGISTER_R9: index_expr = state.r9; break;
					case ZYDIS_REGISTER_R9D: index_expr = state.r9; break;
					case ZYDIS_REGISTER_R9W: index_expr = state.r9; break;
					case ZYDIS_REGISTER_R9B: index_expr = state.r9; break;

					case ZYDIS_REGISTER_R10: index_expr = state.r10; break;
					case ZYDIS_REGISTER_R10D: index_expr = state.r10; break;
					case ZYDIS_REGISTER_R10W: index_expr = state.r10; break;
					case ZYDIS_REGISTER_R10B: index_expr = state.r10; break;

					case ZYDIS_REGISTER_R11: index_expr = state.r11; break;
					case ZYDIS_REGISTER_R11D: index_expr = state.r11; break;
					case ZYDIS_REGISTER_R11W: index_expr = state.r11; break;
					case ZYDIS_REGISTER_R11B: index_expr = state.r11; break;

					case ZYDIS_REGISTER_R12: index_expr = state.r12; break;
					case ZYDIS_REGISTER_R12D: index_expr = state.r12; break;
					case ZYDIS_REGISTER_R12W: index_expr = state.r12; break;
					case ZYDIS_REGISTER_R12B: index_expr = state.r12; break;

					case ZYDIS_REGISTER_R13: index_expr = state.r13; break;
					case ZYDIS_REGISTER_R13D: index_expr = state.r13; break;
					case ZYDIS_REGISTER_R13W: index_expr = state.r13; break;
					case ZYDIS_REGISTER_R13B: index_expr = state.r13; break;

					case ZYDIS_REGISTER_R14: index_expr = state.r14; break;
					case ZYDIS_REGISTER_R14D: index_expr = state.r14; break;
					case ZYDIS_REGISTER_R14W: index_expr = state.r14; break;
					case ZYDIS_REGISTER_R14B: index_expr = state.r14; break;

					case ZYDIS_REGISTER_R15: index_expr = state.r15; break;
					case ZYDIS_REGISTER_R15D: index_expr = state.r15; break;
					case ZYDIS_REGISTER_R15W: index_expr = state.r15; break;
					case ZYDIS_REGISTER_R15B: index_expr = state.r15; break;

					default:
						throw std::exception("bad register");
					}
				}

				if (op.mem.disp.has_displacement)
				{
					disp_expr = new z3::expr(z3c.bv_val(static_cast<uint64_t>(op.mem.disp.value), 64));
				}

				if (index_expr)
				{
					base_expr = *ret + *index_expr;
				}

				if (disp_expr)
				{
					base_expr += *disp_expr;
				}

				state.immediate.push_back(base_expr);

				return &state.immediate.back();
			}
			else
				throw std::exception("bad state");
		}
		else
			throw std::exception("bad operand type in get_val_expr function");
	}

	static inline bool calculate_parity__(uint64_t num)
	{
		uint64_t count = 0;

		while (num > 0) {
			if (num & 1) {
				count++;
			}
			num >>= 1;
		}

		bool isEven = (count % 2 == 0);

		std::cout << std::boolalpha << isEven << std::endl;
		return isEven;
	}

	static inline uint64_t get_val_reg64(uc_engine* uc, ZydisDecodedOperand op)
	{
		uint64_t Val = 0;
		if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
		{
			switch (op.reg.value)
			{
			case ZYDIS_REGISTER_RAX: uc_reg_read(uc, UC_X86_REG_RAX, &Val); return Val;
			case ZYDIS_REGISTER_EAX: uc_reg_read(uc, UC_X86_REG_EAX, &Val); return Val;
			case ZYDIS_REGISTER_AX: uc_reg_read(uc, UC_X86_REG_AX, &Val); return Val;
			case ZYDIS_REGISTER_AH: uc_reg_read(uc, UC_X86_REG_AH, &Val); return Val;
			case ZYDIS_REGISTER_AL: uc_reg_read(uc, UC_X86_REG_AL, &Val); return Val;

			case ZYDIS_REGISTER_RBX: uc_reg_read(uc, UC_X86_REG_RBX, &Val); return Val;
			case ZYDIS_REGISTER_EBX: uc_reg_read(uc, UC_X86_REG_EBX, &Val); return Val;
			case ZYDIS_REGISTER_BX: uc_reg_read(uc, UC_X86_REG_BX, &Val); return Val;
			case ZYDIS_REGISTER_BH: uc_reg_read(uc, UC_X86_REG_BH, &Val); return Val;
			case ZYDIS_REGISTER_BL: uc_reg_read(uc, UC_X86_REG_BL, &Val); return Val;

			case ZYDIS_REGISTER_RCX: uc_reg_read(uc, UC_X86_REG_RCX, &Val); return Val;
			case ZYDIS_REGISTER_ECX: uc_reg_read(uc, UC_X86_REG_ECX, &Val); return Val;
			case ZYDIS_REGISTER_CX: uc_reg_read(uc, UC_X86_REG_CX, &Val); return Val;
			case ZYDIS_REGISTER_CH: uc_reg_read(uc, UC_X86_REG_CH, &Val); return Val;
			case ZYDIS_REGISTER_CL: uc_reg_read(uc, UC_X86_REG_CL, &Val); return Val;

			case ZYDIS_REGISTER_RDX: uc_reg_read(uc, UC_X86_REG_RDX, &Val); return Val;
			case ZYDIS_REGISTER_EDX: uc_reg_read(uc, UC_X86_REG_EDX, &Val); return Val;
			case ZYDIS_REGISTER_DX: uc_reg_read(uc, UC_X86_REG_DX, &Val); return Val;
			case ZYDIS_REGISTER_DH: uc_reg_read(uc, UC_X86_REG_DH, &Val); return Val;
			case ZYDIS_REGISTER_DL: uc_reg_read(uc, UC_X86_REG_DL, &Val); return Val;

			case ZYDIS_REGISTER_RBP: uc_reg_read(uc, UC_X86_REG_RBP, &Val); return Val;
			case ZYDIS_REGISTER_EBP: uc_reg_read(uc, UC_X86_REG_EBP, &Val); return Val;
			case ZYDIS_REGISTER_BP: uc_reg_read(uc, UC_X86_REG_BP, &Val); return Val;
			case ZYDIS_REGISTER_BPL: uc_reg_read(uc, UC_X86_REG_BPL, &Val); return Val;

			case ZYDIS_REGISTER_RSP: uc_reg_read(uc, UC_X86_REG_RSP, &Val); return Val;
			case ZYDIS_REGISTER_ESP: uc_reg_read(uc, UC_X86_REG_ESP, &Val); return Val;
			case ZYDIS_REGISTER_SP: uc_reg_read(uc, UC_X86_REG_SP, &Val); return Val;
			case ZYDIS_REGISTER_SPL: uc_reg_read(uc, UC_X86_REG_SPL, &Val); return Val;

			case ZYDIS_REGISTER_RSI: uc_reg_read(uc, UC_X86_REG_RSI, &Val); return Val;
			case ZYDIS_REGISTER_ESI: uc_reg_read(uc, UC_X86_REG_ESI, &Val); return Val;
			case ZYDIS_REGISTER_SI: uc_reg_read(uc, UC_X86_REG_SI, &Val); return Val;
			case ZYDIS_REGISTER_SIL: uc_reg_read(uc, UC_X86_REG_SIL, &Val); return Val;

			case ZYDIS_REGISTER_RDI: uc_reg_read(uc, UC_X86_REG_RDI, &Val); return Val;
			case ZYDIS_REGISTER_EDI: uc_reg_read(uc, UC_X86_REG_EDI, &Val); return Val;
			case ZYDIS_REGISTER_DI: uc_reg_read(uc, UC_X86_REG_DI, &Val); return Val;
			case ZYDIS_REGISTER_DIL: uc_reg_read(uc, UC_X86_REG_DIL, &Val); return Val;

			case ZYDIS_REGISTER_R8: uc_reg_read(uc, UC_X86_REG_R8, &Val); return Val;
			case ZYDIS_REGISTER_R8D: uc_reg_read(uc, UC_X86_REG_R8D, &Val); return Val;
			case ZYDIS_REGISTER_R8W: uc_reg_read(uc, UC_X86_REG_R8W, &Val); return Val;
			case ZYDIS_REGISTER_R8B: uc_reg_read(uc, UC_X86_REG_R8B, &Val); return Val;

			case ZYDIS_REGISTER_R9: uc_reg_read(uc, UC_X86_REG_R9, &Val); return Val;
			case ZYDIS_REGISTER_R9D: uc_reg_read(uc, UC_X86_REG_R9D, &Val); return Val;
			case ZYDIS_REGISTER_R9W: uc_reg_read(uc, UC_X86_REG_R9W, &Val); return Val;
			case ZYDIS_REGISTER_R9B: uc_reg_read(uc, UC_X86_REG_R9B, &Val); return Val;

			case ZYDIS_REGISTER_R10: uc_reg_read(uc, UC_X86_REG_R10, &Val); return Val;
			case ZYDIS_REGISTER_R10D: uc_reg_read(uc, UC_X86_REG_R10D, &Val); return Val;
			case ZYDIS_REGISTER_R10W: uc_reg_read(uc, UC_X86_REG_R10W, &Val); return Val;
			case ZYDIS_REGISTER_R10B: uc_reg_read(uc, UC_X86_REG_R10B, &Val); return Val;

			case ZYDIS_REGISTER_R11: uc_reg_read(uc, UC_X86_REG_R11, &Val); return Val;
			case ZYDIS_REGISTER_R11D: uc_reg_read(uc, UC_X86_REG_R11D, &Val); return Val;
			case ZYDIS_REGISTER_R11W: uc_reg_read(uc, UC_X86_REG_R11W, &Val); return Val;
			case ZYDIS_REGISTER_R11B: uc_reg_read(uc, UC_X86_REG_R11B, &Val); return Val;

			case ZYDIS_REGISTER_R12: uc_reg_read(uc, UC_X86_REG_R12, &Val); return Val;
			case ZYDIS_REGISTER_R12D: uc_reg_read(uc, UC_X86_REG_R12D, &Val); return Val;
			case ZYDIS_REGISTER_R12W: uc_reg_read(uc, UC_X86_REG_R12W, &Val); return Val;
			case ZYDIS_REGISTER_R12B: uc_reg_read(uc, UC_X86_REG_R12B, &Val); return Val;

			case ZYDIS_REGISTER_R13: uc_reg_read(uc, UC_X86_REG_R13, &Val); return Val;
			case ZYDIS_REGISTER_R13D: uc_reg_read(uc, UC_X86_REG_R13D, &Val); return Val;
			case ZYDIS_REGISTER_R13W: uc_reg_read(uc, UC_X86_REG_R13W, &Val); return Val;
			case ZYDIS_REGISTER_R13B: uc_reg_read(uc, UC_X86_REG_R13B, &Val); return Val;

			case ZYDIS_REGISTER_R14: uc_reg_read(uc, UC_X86_REG_R14, &Val); return Val;
			case ZYDIS_REGISTER_R14D: uc_reg_read(uc, UC_X86_REG_R14D, &Val); return Val;
			case ZYDIS_REGISTER_R14W: uc_reg_read(uc, UC_X86_REG_R14W, &Val); return Val;
			case ZYDIS_REGISTER_R14B: uc_reg_read(uc, UC_X86_REG_R14B, &Val); return Val;

			case ZYDIS_REGISTER_R15: uc_reg_read(uc, UC_X86_REG_R15, &Val); return Val;
			case ZYDIS_REGISTER_R15D: uc_reg_read(uc, UC_X86_REG_R15D, &Val); return Val;
			case ZYDIS_REGISTER_R15W: uc_reg_read(uc, UC_X86_REG_R15W, &Val); return Val;
			case ZYDIS_REGISTER_R15B: uc_reg_read(uc, UC_X86_REG_R15B, &Val); return Val;

			case ZYDIS_REGISTER_RFLAGS: uc_reg_read(uc, UC_X86_REG_RFLAGS, &Val); return Val;

			default:
				throw std::exception("bad register");
			}
		}
		else if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
		{
			uint64_t Val = static_cast<uint64_t>(op.imm.value.u); return Val;
		}
		/*
		else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
		{
			if (op.mem.base != ZYDIS_REGISTER_NONE)
			{
				switch (op.mem.base)
				{
				case ZYDIS_REGISTER_RAX: uc_reg_read(uc, UC_X86_REG_RAX, &Val); break;
				case ZYDIS_REGISTER_EAX: uc_reg_read(uc, UC_X86_REG_EAX, &Val); break;
				case ZYDIS_REGISTER_AX: uc_reg_read(uc, UC_X86_REG_AX, &Val); break;
				case ZYDIS_REGISTER_AH: uc_reg_read(uc, UC_X86_REG_AH, &Val); break;
				case ZYDIS_REGISTER_AL: uc_reg_read(uc, UC_X86_REG_AL, &Val); break;

				case ZYDIS_REGISTER_RBX: uc_reg_read(uc, UC_X86_REG_RBX, &Val); return Val;
				case ZYDIS_REGISTER_EBX: uc_reg_read(uc, UC_X86_REG_EBX, &Val); return Val;
				case ZYDIS_REGISTER_BX: uc_reg_read(uc, UC_X86_REG_BX, &Val); return Val;
				case ZYDIS_REGISTER_BH: uc_reg_read(uc, UC_X86_REG_BH, &Val); return Val;
				case ZYDIS_REGISTER_BL: uc_reg_read(uc, UC_X86_REG_BL, &Val); return Val;

				case ZYDIS_REGISTER_RCX: uc_reg_read(uc, UC_X86_REG_RCX, &Val); return Val;
				case ZYDIS_REGISTER_ECX: uc_reg_read(uc, UC_X86_REG_ECX, &Val); return Val;
				case ZYDIS_REGISTER_CX: uc_reg_read(uc, UC_X86_REG_CX, &Val); return Val;
				case ZYDIS_REGISTER_CH: uc_reg_read(uc, UC_X86_REG_CH, &Val); return Val;
				case ZYDIS_REGISTER_CL: uc_reg_read(uc, UC_X86_REG_CL, &Val); return Val;

				case ZYDIS_REGISTER_RDX: uc_reg_read(uc, UC_X86_REG_RDX, &Val); return Val;
				case ZYDIS_REGISTER_EDX: uc_reg_read(uc, UC_X86_REG_EDX, &Val); return Val;
				case ZYDIS_REGISTER_DX: uc_reg_read(uc, UC_X86_REG_DX, &Val); return Val;
				case ZYDIS_REGISTER_DH: uc_reg_read(uc, UC_X86_REG_DH, &Val); return Val;
				case ZYDIS_REGISTER_DL: uc_reg_read(uc, UC_X86_REG_DL, &Val); return Val;

				case ZYDIS_REGISTER_RBP: uc_reg_read(uc, UC_X86_REG_RBP, &Val); return Val;
				case ZYDIS_REGISTER_EBP: uc_reg_read(uc, UC_X86_REG_EBP, &Val); return Val;
				case ZYDIS_REGISTER_BP: uc_reg_read(uc, UC_X86_REG_BP, &Val); return Val;
				case ZYDIS_REGISTER_BPL: uc_reg_read(uc, UC_X86_REG_BPL, &Val); return Val;

				case ZYDIS_REGISTER_RSP: uc_reg_read(uc, UC_X86_REG_RSP, &Val); return Val;
				case ZYDIS_REGISTER_ESP: uc_reg_read(uc, UC_X86_REG_ESP, &Val); return Val;
				case ZYDIS_REGISTER_SP: uc_reg_read(uc, UC_X86_REG_SP, &Val); return Val;
				case ZYDIS_REGISTER_SPL: uc_reg_read(uc, UC_X86_REG_SPL, &Val); return Val;

				case ZYDIS_REGISTER_RSI: uc_reg_read(uc, UC_X86_REG_RSI, &Val); return Val;
				case ZYDIS_REGISTER_ESI: uc_reg_read(uc, UC_X86_REG_ESI, &Val); return Val;
				case ZYDIS_REGISTER_SI: uc_reg_read(uc, UC_X86_REG_SI, &Val); return Val;
				case ZYDIS_REGISTER_SIL: uc_reg_read(uc, UC_X86_REG_SIL, &Val); return Val;

				case ZYDIS_REGISTER_RDI: uc_reg_read(uc, UC_X86_REG_RDI, &Val); return Val;
				case ZYDIS_REGISTER_EDI: uc_reg_read(uc, UC_X86_REG_EDI, &Val); return Val;
				case ZYDIS_REGISTER_DI: uc_reg_read(uc, UC_X86_REG_DI, &Val); return Val;
				case ZYDIS_REGISTER_DIL: uc_reg_read(uc, UC_X86_REG_DIL, &Val); return Val;

				case ZYDIS_REGISTER_R8: uc_reg_read(uc, UC_X86_REG_R8, &Val); return Val;
				case ZYDIS_REGISTER_R8D: uc_reg_read(uc, UC_X86_REG_R8D, &Val); return Val;
				case ZYDIS_REGISTER_R8W: uc_reg_read(uc, UC_X86_REG_R8W, &Val); return Val;
				case ZYDIS_REGISTER_R8B: uc_reg_read(uc, UC_X86_REG_R8B, &Val); return Val;

				case ZYDIS_REGISTER_R9: uc_reg_read(uc, UC_X86_REG_R9, &Val); return Val;
				case ZYDIS_REGISTER_R9D: uc_reg_read(uc, UC_X86_REG_R9D, &Val); return Val;
				case ZYDIS_REGISTER_R9W: uc_reg_read(uc, UC_X86_REG_R9W, &Val); return Val;
				case ZYDIS_REGISTER_R9B: uc_reg_read(uc, UC_X86_REG_R9B, &Val); return Val;

				case ZYDIS_REGISTER_R10: uc_reg_read(uc, UC_X86_REG_R10, &Val); return Val;
				case ZYDIS_REGISTER_R10D: uc_reg_read(uc, UC_X86_REG_R10D, &Val); return Val;
				case ZYDIS_REGISTER_R10W: uc_reg_read(uc, UC_X86_REG_R10W, &Val); return Val;
				case ZYDIS_REGISTER_R10B: uc_reg_read(uc, UC_X86_REG_R10B, &Val); return Val;

				case ZYDIS_REGISTER_R11: uc_reg_read(uc, UC_X86_REG_R11, &Val); return Val;
				case ZYDIS_REGISTER_R11D: uc_reg_read(uc, UC_X86_REG_R11D, &Val); return Val;
				case ZYDIS_REGISTER_R11W: uc_reg_read(uc, UC_X86_REG_R11W, &Val); return Val;
				case ZYDIS_REGISTER_R11B: uc_reg_read(uc, UC_X86_REG_R11B, &Val); return Val;

				case ZYDIS_REGISTER_R12: uc_reg_read(uc, UC_X86_REG_R12, &Val); return Val;
				case ZYDIS_REGISTER_R12D: uc_reg_read(uc, UC_X86_REG_R12D, &Val); return Val;
				case ZYDIS_REGISTER_R12W: uc_reg_read(uc, UC_X86_REG_R12W, &Val); return Val;
				case ZYDIS_REGISTER_R12B: uc_reg_read(uc, UC_X86_REG_R12B, &Val); return Val;

				case ZYDIS_REGISTER_R13: uc_reg_read(uc, UC_X86_REG_R13, &Val); return Val;
				case ZYDIS_REGISTER_R13D: uc_reg_read(uc, UC_X86_REG_R13D, &Val); return Val;
				case ZYDIS_REGISTER_R13W: uc_reg_read(uc, UC_X86_REG_R13W, &Val); return Val;
				case ZYDIS_REGISTER_R13B: uc_reg_read(uc, UC_X86_REG_R13B, &Val); return Val;

				case ZYDIS_REGISTER_R14: uc_reg_read(uc, UC_X86_REG_R14, &Val); return Val;
				case ZYDIS_REGISTER_R14D: uc_reg_read(uc, UC_X86_REG_R14D, &Val); return Val;
				case ZYDIS_REGISTER_R14W: uc_reg_read(uc, UC_X86_REG_R14W, &Val); return Val;
				case ZYDIS_REGISTER_R14B: uc_reg_read(uc, UC_X86_REG_R14B, &Val); return Val;

				case ZYDIS_REGISTER_R15: uc_reg_read(uc, UC_X86_REG_R15, &Val); return Val;
				case ZYDIS_REGISTER_R15D: uc_reg_read(uc, UC_X86_REG_R15D, &Val); return Val;
				case ZYDIS_REGISTER_R15W: uc_reg_read(uc, UC_X86_REG_R15W, &Val); return Val;
				case ZYDIS_REGISTER_R15B: uc_reg_read(uc, UC_X86_REG_R15B, &Val); return Val;

				case ZYDIS_REGISTER_RFLAGS: uc_reg_read(uc, UC_X86_REG_RFLAGS, &Val); return Val;

				default:
					throw std::exception("bad register");
				}
			}
			if (op.mem.index != ZYDIS_REGISTER_NONE)
			{
				switch (op.mem.index)
				{
				case ZYDIS_REGISTER_RAX: uc_reg_read(uc, UC_X86_REG_RAX, &Val); return Val;
				case ZYDIS_REGISTER_EAX: uc_reg_read(uc, UC_X86_REG_EAX, &Val); return Val;
				case ZYDIS_REGISTER_AX: uc_reg_read(uc, UC_X86_REG_AX, &Val); return Val;
				case ZYDIS_REGISTER_AH: uc_reg_read(uc, UC_X86_REG_AH, &Val); return Val;
				case ZYDIS_REGISTER_AL: uc_reg_read(uc, UC_X86_REG_AL, &Val); return Val;

				case ZYDIS_REGISTER_RBX: uc_reg_read(uc, UC_X86_REG_RBX, &Val); return Val;
				case ZYDIS_REGISTER_EBX: uc_reg_read(uc, UC_X86_REG_EBX, &Val); return Val;
				case ZYDIS_REGISTER_BX: uc_reg_read(uc, UC_X86_REG_BX, &Val); return Val;
				case ZYDIS_REGISTER_BH: uc_reg_read(uc, UC_X86_REG_BH, &Val); return Val;
				case ZYDIS_REGISTER_BL: uc_reg_read(uc, UC_X86_REG_BL, &Val); return Val;

				case ZYDIS_REGISTER_RCX: uc_reg_read(uc, UC_X86_REG_RCX, &Val); return Val;
				case ZYDIS_REGISTER_ECX: uc_reg_read(uc, UC_X86_REG_ECX, &Val); return Val;
				case ZYDIS_REGISTER_CX: uc_reg_read(uc, UC_X86_REG_CX, &Val); return Val;
				case ZYDIS_REGISTER_CH: uc_reg_read(uc, UC_X86_REG_CH, &Val); return Val;
				case ZYDIS_REGISTER_CL: uc_reg_read(uc, UC_X86_REG_CL, &Val); return Val;

				case ZYDIS_REGISTER_RDX: uc_reg_read(uc, UC_X86_REG_RDX, &Val); return Val;
				case ZYDIS_REGISTER_EDX: uc_reg_read(uc, UC_X86_REG_EDX, &Val); return Val;
				case ZYDIS_REGISTER_DX: uc_reg_read(uc, UC_X86_REG_DX, &Val); return Val;
				case ZYDIS_REGISTER_DH: uc_reg_read(uc, UC_X86_REG_DH, &Val); return Val;
				case ZYDIS_REGISTER_DL: uc_reg_read(uc, UC_X86_REG_DL, &Val); return Val;

				case ZYDIS_REGISTER_RBP: uc_reg_read(uc, UC_X86_REG_RBP, &Val); return Val;
				case ZYDIS_REGISTER_EBP: uc_reg_read(uc, UC_X86_REG_EBP, &Val); return Val;
				case ZYDIS_REGISTER_BP: uc_reg_read(uc, UC_X86_REG_BP, &Val); return Val;
				case ZYDIS_REGISTER_BPL: uc_reg_read(uc, UC_X86_REG_BPL, &Val); return Val;

				case ZYDIS_REGISTER_RSP: uc_reg_read(uc, UC_X86_REG_RSP, &Val); return Val;
				case ZYDIS_REGISTER_ESP: uc_reg_read(uc, UC_X86_REG_ESP, &Val); return Val;
				case ZYDIS_REGISTER_SP: uc_reg_read(uc, UC_X86_REG_SP, &Val); return Val;
				case ZYDIS_REGISTER_SPL: uc_reg_read(uc, UC_X86_REG_SPL, &Val); return Val;

				case ZYDIS_REGISTER_RSI: uc_reg_read(uc, UC_X86_REG_RSI, &Val); return Val;
				case ZYDIS_REGISTER_ESI: uc_reg_read(uc, UC_X86_REG_ESI, &Val); return Val;
				case ZYDIS_REGISTER_SI: uc_reg_read(uc, UC_X86_REG_SI, &Val); return Val;
				case ZYDIS_REGISTER_SIL: uc_reg_read(uc, UC_X86_REG_SIL, &Val); return Val;

				case ZYDIS_REGISTER_RDI: uc_reg_read(uc, UC_X86_REG_RDI, &Val); return Val;
				case ZYDIS_REGISTER_EDI: uc_reg_read(uc, UC_X86_REG_EDI, &Val); return Val;
				case ZYDIS_REGISTER_DI: uc_reg_read(uc, UC_X86_REG_DI, &Val); return Val;
				case ZYDIS_REGISTER_DIL: uc_reg_read(uc, UC_X86_REG_DIL, &Val); return Val;

				case ZYDIS_REGISTER_R8: uc_reg_read(uc, UC_X86_REG_R8, &Val); return Val;
				case ZYDIS_REGISTER_R8D: uc_reg_read(uc, UC_X86_REG_R8D, &Val); return Val;
				case ZYDIS_REGISTER_R8W: uc_reg_read(uc, UC_X86_REG_R8W, &Val); return Val;
				case ZYDIS_REGISTER_R8B: uc_reg_read(uc, UC_X86_REG_R8B, &Val); return Val;

				case ZYDIS_REGISTER_R9: uc_reg_read(uc, UC_X86_REG_R9, &Val); return Val;
				case ZYDIS_REGISTER_R9D: uc_reg_read(uc, UC_X86_REG_R9D, &Val); return Val;
				case ZYDIS_REGISTER_R9W: uc_reg_read(uc, UC_X86_REG_R9W, &Val); return Val;
				case ZYDIS_REGISTER_R9B: uc_reg_read(uc, UC_X86_REG_R9B, &Val); return Val;

				case ZYDIS_REGISTER_R10: uc_reg_read(uc, UC_X86_REG_R10, &Val); return Val;
				case ZYDIS_REGISTER_R10D: uc_reg_read(uc, UC_X86_REG_R10D, &Val); return Val;
				case ZYDIS_REGISTER_R10W: uc_reg_read(uc, UC_X86_REG_R10W, &Val); return Val;
				case ZYDIS_REGISTER_R10B: uc_reg_read(uc, UC_X86_REG_R10B, &Val); return Val;

				case ZYDIS_REGISTER_R11: uc_reg_read(uc, UC_X86_REG_R11, &Val); return Val;
				case ZYDIS_REGISTER_R11D: uc_reg_read(uc, UC_X86_REG_R11D, &Val); return Val;
				case ZYDIS_REGISTER_R11W: uc_reg_read(uc, UC_X86_REG_R11W, &Val); return Val;
				case ZYDIS_REGISTER_R11B: uc_reg_read(uc, UC_X86_REG_R11B, &Val); return Val;

				case ZYDIS_REGISTER_R12: uc_reg_read(uc, UC_X86_REG_R12, &Val); return Val;
				case ZYDIS_REGISTER_R12D: uc_reg_read(uc, UC_X86_REG_R12D, &Val); return Val;
				case ZYDIS_REGISTER_R12W: uc_reg_read(uc, UC_X86_REG_R12W, &Val); return Val;
				case ZYDIS_REGISTER_R12B: uc_reg_read(uc, UC_X86_REG_R12B, &Val); return Val;

				case ZYDIS_REGISTER_R13: uc_reg_read(uc, UC_X86_REG_R13, &Val); return Val;
				case ZYDIS_REGISTER_R13D: uc_reg_read(uc, UC_X86_REG_R13D, &Val); return Val;
				case ZYDIS_REGISTER_R13W: uc_reg_read(uc, UC_X86_REG_R13W, &Val); return Val;
				case ZYDIS_REGISTER_R13B: uc_reg_read(uc, UC_X86_REG_R13B, &Val); return Val;

				case ZYDIS_REGISTER_R14: uc_reg_read(uc, UC_X86_REG_R14, &Val); return Val;
				case ZYDIS_REGISTER_R14D: uc_reg_read(uc, UC_X86_REG_R14D, &Val); return Val;
				case ZYDIS_REGISTER_R14W: uc_reg_read(uc, UC_X86_REG_R14W, &Val); return Val;
				case ZYDIS_REGISTER_R14B: uc_reg_read(uc, UC_X86_REG_R14B, &Val); return Val;

				case ZYDIS_REGISTER_R15: uc_reg_read(uc, UC_X86_REG_R15, &Val); return Val;
				case ZYDIS_REGISTER_R15D: uc_reg_read(uc, UC_X86_REG_R15D, &Val); return Val;
				case ZYDIS_REGISTER_R15W: uc_reg_read(uc, UC_X86_REG_R15W, &Val); return Val;
				case ZYDIS_REGISTER_R15B: uc_reg_read(uc, UC_X86_REG_R15B, &Val); return Val;

				case ZYDIS_REGISTER_RFLAGS: uc_reg_read(uc, UC_X86_REG_RFLAGS, &Val); return Val;

				default:
					throw std::exception("bad register");
				}
			}

		}
		*/
		else
			throw std::exception("bad operand type in get_val_reg64 function");
	}
}

namespace AsmX64InstrsTranslate {

	namespace non_algebraic
	{
		static inline void translate_mov(z3::context& z3c, x8664_ctx& old_state, x8664_ctx& new_state, ZydisDisassembledInstruction ins)
		{
			if (ins.info.operand_count_visible == 2)
			{
				auto& op1 = ins.operands[0];
				auto& op2 = ins.operands[1];

				z3::expr e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);
				z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);

				*dst = new z3::expr(z3c, e2);
			}
			else
				throw std::exception("bad operand count in translate_mov func");
		}

		static inline void translate_lea(z3::context& z3c, x8664_ctx& old_state, x8664_ctx& new_state, ZydisDisassembledInstruction ins)
		{
			if (ins.info.operand_count_visible == 2)
			{
				auto& op1 = ins.operands[0];
				auto& op2 = ins.operands[1];

				z3::expr e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);
				z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);

				*dst = new z3::expr(e2);
			}
			else
				throw std::exception("bad operand count in translate_lea function");
		}
		
		static inline void translate_push(z3::context& z3c, x8664_ctx& old_state, x8664_ctx& new_state, ZydisDisassembledInstruction ins)
		{
			if (ins.info.operand_count_visible == 1)
			{
				auto& op1 = ins.operands[0];
				auto& op2 = ins.operands[1];

				z3::expr e1 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op1);

				new_state.rsp = new z3::expr(*old_state.rsp - 8);
				z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op2);

				*dst = new z3::expr(z3c, e1);
			}
			else
				throw std::exception("bad operand count in translate_push instruction");
		}

		static inline void translate_pop(z3::context& z3c, x8664_ctx& old_state, x8664_ctx& new_state, ZydisDisassembledInstruction ins)
		{
			if (ins.info.operand_count_visible == 1)
			{
				auto& op1 = ins.operands[0];
				auto& op2 = ins.operands[1];

				z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);
			
				*dst = new z3::expr(z3c, *old_state.rsp);

				new_state.rsp = new z3::expr(*old_state.rsp + 8);
			}
			else
				throw std::exception("bad operand count in translate_pop instruction");
		}

		static inline void translate_pushfq(z3::context& z3c, x8664_ctx& old_state, x8664_ctx& new_state, ZydisDisassembledInstruction ins)
		{
			if (ins.info.operand_count_visible == 0)
			{
				auto& op1 = ins.operands[0];

				z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);

				*dst = new z3::expr(z3c, *old_state.rflags);

				new_state.rsp = new z3::expr(*old_state.rsp - 8);
			}
			else
				throw std::exception("bad operand count in translate_pushfq instuction");
		}

		static inline void translate_popfq(z3::context& z3c, x8664_ctx& old_state, x8664_ctx& new_state, ZydisDisassembledInstruction ins)
		{
			if (ins.info.operand_count_visible == 0)
			{
				auto& op1 = ins.operands[0];

				z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);

				*dst = new z3::expr(z3c, *old_state.rflags);

				new_state.rsp = new z3::expr(*old_state.rsp + 8);
			}
			else
				throw std::exception("bad operand count in translate_popfq instruction");
		}
	}

	namespace algebraic
	{
		namespace arithmetic
		{
			static inline void translate_add(
				uc_engine* uc,
				z3::context& z3c, 
				x8664_ctx& old_state, 
				x8664_ctx& new_state, 
				ZydisDisassembledInstruction ins)
			{
				if (ins.info.operand_count_visible == 2)
				{
					auto& op1 = ins.operands[0];
					auto& op2 = ins.operands[1];

					z3::expr e1 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op1);
					z3::expr e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);

					z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);
					uint64_t add = Z3SystemTranslateFuncs::get_val_reg64(uc, op1) + Z3SystemTranslateFuncs::get_val_reg64(uc, op2);

					*dst = new z3::expr(z3c, e1 + e2);
					
					new_state.zf = new z3::expr((**dst).simplify() == 0);
					new_state.of = new z3::expr(((e1 ^ e2) & 0x7FFFFFFF) == 0 && ((e1 ^ (**dst).simplify()) & 0x7FFFFFFF) != 0);
					new_state.cf = new z3::expr((**dst).simplify() < e1.simplify());
					new_state.pf = new z3::expr(z3c.bool_val(Z3SystemTranslateFuncs::calculate_parity__(add)));
					new_state.sf = new z3::expr((**dst).simplify() < 0);

					z3::expr bit3 = (**dst).simplify().extract(3, 3);
					z3::expr bit4 = (**dst).simplify().extract(4, 4);
					new_state.af = new z3::expr((bit3 ^ bit4) != 0);
				}
				else
					throw std::exception("bad operand count in translate_add function");
			}
			
			static inline void translate_sub(
				uc_engine* uc,
				z3::context& z3c, 
				x8664_ctx& old_state, 
				x8664_ctx& new_state, 
				ZydisDisassembledInstruction ins)
			{
				if (ins.info.operand_count_visible == 2)
				{
					auto& op1 = ins.operands[0];
					auto& op2 = ins.operands[1];

					z3::expr e1 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op1);
					z3::expr e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);

					z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);
					uint64_t sub = Z3SystemTranslateFuncs::get_val_reg64(uc, op1) - Z3SystemTranslateFuncs::get_val_reg64(uc, op2);

					*dst = new z3::expr(z3c, e1 - e2);

					new_state.zf = new z3::expr((**dst).simplify() == 0);
					new_state.of = new z3::expr(((e1 ^ e2) & 0x7FFFFFFF) != 0 && ((e1 ^ (**dst).simplify()) & 0x7FFFFFFF) != 0);
					new_state.cf = new z3::expr((**dst).simplify() > e1.simplify());
					new_state.pf = new z3::expr(z3c.bool_val(Z3SystemTranslateFuncs::calculate_parity__(sub)));
					new_state.sf = new z3::expr((**dst).simplify() < 0);

					z3::expr bit3 = (**dst).simplify().extract(3, 3);
					z3::expr bit4 = (**dst).simplify().extract(4, 4);
					new_state.af = new z3::expr((bit3 ^ bit4) != 0);
				}
				else
					throw std::exception("bad operand count in translate_sub function");
			}	

			static inline void translate_test(
				uc_engine* uc, 
				z3::context& z3c, 
				x8664_ctx& old_state, 
				x8664_ctx& new_state, 
				ZydisDisassembledInstruction ins)
			{
				if (ins.info.operand_count_visible == 2)
				{
					auto& op1 = ins.operands[0];
					auto& op2 = ins.operands[1];

					z3::expr e1 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op1);
					z3::expr e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);

					z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);

					uint64_t utest = Z3SystemTranslateFuncs::get_val_reg64(uc, op1) * Z3SystemTranslateFuncs::get_val_reg64(uc, op2);

					z3::expr test = e1 * e2;
					*dst = new z3::expr(z3c, e1);

					new_state.zf = new z3::expr(test.simplify() == 0);
					new_state.of = new z3::expr(((e1 ^ e2) & 0x7FFFFFFF) != 0 && ((e1 ^ test.simplify()) & 0x7FFFFFFF) != 0);
					new_state.cf = new z3::expr((test.simplify()) < e1.simplify());
					new_state.pf = new z3::expr(z3c.bool_val(Z3SystemTranslateFuncs::calculate_parity__(utest)));

					new_state.sf = new z3::expr(test.simplify() < 0);
				}
				else
					throw std::exception("bad operand count in translate_test function");
			}

			static inline void translate_cmp(
				uc_engine* uc, 
				z3::context& z3c, 
				x8664_ctx& old_state, 
				x8664_ctx& new_state, 
				ZydisDisassembledInstruction ins)
			{
				if (ins.info.operand_count_visible == 2)
				{
					auto& op1 = ins.operands[0];
					auto& op2 = ins.operands[1];

					z3::expr e1 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op1);
					z3::expr e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);

					z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);
					uint64_t ucmp = Z3SystemTranslateFuncs::get_val_reg64(uc, op1) - Z3SystemTranslateFuncs::get_val_reg64(uc, op2);

					z3::expr cmp = e1 - e2;
					*dst = new z3::expr(z3c, e1);

					new_state.zf = new z3::expr(cmp.simplify() == 0);
					new_state.of = new z3::expr(((e1 ^ e2) & 0x7FFFFFFF) != 0 && ((e1 ^ cmp.simplify()) & 0x7FFFFFFF) != 0);
					new_state.cf = new z3::expr((cmp).simplify() > e1.simplify());
					new_state.pf = new z3::expr(z3c.bool_val(Z3SystemTranslateFuncs::calculate_parity__(ucmp)));
					new_state.sf = new z3::expr(cmp.simplify() < 0);

					z3::expr bit3 = (cmp.simplify()).extract(3, 3);
					z3::expr bit4 = (cmp.simplify()).extract(4, 4);
					new_state.af = new z3::expr((bit3 ^ bit4) != 0);
				}
				else
					throw std::exception("bad operand count in translate_cmp function");
			}
		}
		

		namespace Bitwise
		{
			static inline void translate_xor(
				uc_engine* uc, 
				z3::context& z3c, 
				x8664_ctx& old_state, 
				x8664_ctx& new_state, 
				ZydisDisassembledInstruction ins)
			{
				if (ins.info.operand_count_visible == 2)
				{
					auto& op1 = ins.operands[0];
					auto& op2 = ins.operands[1];

					z3::expr e1 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op1);
					z3::expr e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);

					z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);

					uint64_t uxor = Z3SystemTranslateFuncs::get_val_reg64(uc, op1) ^ Z3SystemTranslateFuncs::get_val_reg64(uc, op2);

					*dst = new z3::expr(z3c, e1^e2);

					new_state.zf = new z3::expr((**dst).simplify() == 0);
					new_state.of = new z3::expr(((e1 ^ e2) & 0x7FFFFFFF) != 0 && ((e1 ^ (**dst).simplify()) & 0x7FFFFFFF) != 0);
					new_state.cf = new z3::expr((**dst).simplify() > e1.simplify());
					new_state.pf = new z3::expr(z3c.bool_val(Z3SystemTranslateFuncs::calculate_parity__(uxor)));
					new_state.sf = new z3::expr((**dst).simplify() < 0);
				}
				else
					throw std::exception("bad operand count in translate_xor function");
			}

			static inline void translate_and(
				uc_engine* uc, 
				z3::context& z3c, 
				x8664_ctx& old_state, 
				x8664_ctx& new_state, 
				ZydisDisassembledInstruction ins)
			{
				if (ins.info.operand_count_visible == 2)
				{
					auto& op1 = ins.operands[0];
					auto& op2 = ins.operands[1];

					z3::expr& e1 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op1);
					z3::expr& e2 = **Z3SystemTranslateFuncs::get_val_expr(z3c, old_state, op2);

					z3::expr** dst = Z3SystemTranslateFuncs::get_val_expr(z3c, new_state, op1);

					uint64_t uand = Z3SystemTranslateFuncs::get_val_reg64(uc, op1) & Z3SystemTranslateFuncs::get_val_reg64(uc, op2);

					*dst = new z3::expr(z3c, e1 & e2);

					new_state.zf = new z3::expr((**dst).simplify() == 0);
					new_state.of = new z3::expr(((e1 ^ e2) & 0x7FFFFFFF) != 0 && ((e1 ^ (**dst).simplify()) & 0x7FFFFFFF) != 0);
					new_state.cf = new z3::expr((**dst).simplify() < e1.simplify());
					new_state.pf = new z3::expr(z3c.bool_val(Z3SystemTranslateFuncs::calculate_parity__(uand)));
					new_state.sf = new z3::expr((**dst).simplify() < 0);
				}
				else
					throw std::exception("bad operand count in translate_and function");
			}
		}
	}

	void InstructionChooser(uc_engine* uc, z3::context& z3c, ZydisDisassembledInstruction ins, x8664_ctx& old_state)
	{
		x8664_ctx new_state;
		switch (ins.info.mnemonic)
		{
		case ZYDIS_MNEMONIC_MOV: AsmX64InstrsTranslate::non_algebraic::translate_mov(z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_PUSH: AsmX64InstrsTranslate::non_algebraic::translate_push(z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_POP: AsmX64InstrsTranslate::non_algebraic::translate_pop(z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_PUSHFQ: AsmX64InstrsTranslate::non_algebraic::translate_pushfq(z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_POPFQ: AsmX64InstrsTranslate::non_algebraic::translate_popfq(z3c, old_state, new_state, ins); break;

		case ZYDIS_MNEMONIC_ADD: AsmX64InstrsTranslate::algebraic::arithmetic::translate_add(uc, z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_SUB: AsmX64InstrsTranslate::algebraic::arithmetic::translate_sub(uc, z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_TEST: AsmX64InstrsTranslate::algebraic::arithmetic::translate_test(uc, z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_CMP: AsmX64InstrsTranslate::algebraic::arithmetic::translate_cmp(uc, z3c, old_state, new_state, ins); break;

		case ZYDIS_MNEMONIC_AND: AsmX64InstrsTranslate::algebraic::Bitwise::translate_and(uc, z3c, old_state, new_state, ins); break;
		case ZYDIS_MNEMONIC_XOR: AsmX64InstrsTranslate::algebraic::Bitwise::translate_xor(uc, z3c, old_state, new_state, ins); break;

		default:
			break;
		}
		new_state.copy_changed_state(old_state, new_state);
	}
}
