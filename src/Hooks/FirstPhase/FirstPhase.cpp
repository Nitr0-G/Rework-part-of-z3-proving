#include "Phases/FirstPhase.hpp"
#include "Phases/PhasePatcher.hpp"
#include "z3/z3states.hpp"
#include "z3/z3ASMx64Instructions.hpp"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <z3++.h>

#include <immintrin.h>
#include <intrin.h>
#include <filesystem>
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <cstdio>
#include <strsafe.h>
#include <Psapi.h>
#include <string>
#include <queue>
#include <fstream>
#include <iostream>
#include <unordered_set>

class opaque_predicate
{
public: 
	enum opaque_predicate_
	{
		not_opaque_predicate,
		opaque_predicate_taken,
		opaque_predicate_not_taken,

		error_opaque_predicate
	};
};

namespace FirstPhase {
	opaque_predicate ObjOpaque_predicate;
	x8664_ctx state; x8664_ctx new_state;
	z3::context z3c;
	namespace OpaquePredicate
	{
		namespace FlagInOpaquePredicate
		{
			enum flag_e
			{
				FLAG_ZF,
				FLAG_OF,
				FLAG_CF,
				FLAG_PF,
				FLAG_SF,
				FLAG_AF,
				FLAG_DF
			};

			static inline z3::expr** get_flag_expr(
				x8664_ctx& state, 
				flag_e flag)
			{
				z3::expr** ret;

				switch (flag)
				{
				case FLAG_ZF: ret = &state.zf; break;
				case FLAG_OF: ret = &state.of; break;
				case FLAG_CF: ret = &state.cf; break;
				case FLAG_PF: ret = &state.pf; break;
				case FLAG_SF: ret = &state.sf; break;
				case FLAG_AF: ret = &state.af; break;
				case FLAG_DF: ret = &state.df; break;
				default:
					throw std::exception("bad flag in get_flag_expr function");
				}

				if (ret)
					return ret;
				else
					throw std::exception("bad state in get_flag_expr function");
			}

			static inline opaque_predicate::opaque_predicate_ ConditionCheck(
				z3::context& z3c, 
				x8664_ctx& state, 
				ZydisDisassembledInstruction ins)
			{
				z3::expr* FlagState = nullptr;

				switch (ins.info.mnemonic)
				{
				case ZYDIS_MNEMONIC_JNBE: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_CF) || !**get_flag_expr(state, FLAG_ZF)); break;
				case ZYDIS_MNEMONIC_JNB: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_CF)); break;
				case ZYDIS_MNEMONIC_JB: FlagState = new z3::expr(**get_flag_expr(state, FLAG_CF)); break;
				case ZYDIS_MNEMONIC_JBE: FlagState = new z3::expr(**get_flag_expr(state, FLAG_CF) || **get_flag_expr(state, FLAG_ZF)); break;

				case ZYDIS_MNEMONIC_JZ: FlagState = new z3::expr(**get_flag_expr(state, FLAG_ZF)); break;
				case ZYDIS_MNEMONIC_JNZ: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_ZF)); break;

				case ZYDIS_MNEMONIC_JNLE: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_SF) != !**get_flag_expr(state, FLAG_OF)); break;
				case ZYDIS_MNEMONIC_JNL: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_SF) != !**get_flag_expr(state, FLAG_OF)); break;
				case ZYDIS_MNEMONIC_JL: FlagState = new z3::expr(**get_flag_expr(state, FLAG_SF) != **get_flag_expr(state, FLAG_OF)); break;
				case ZYDIS_MNEMONIC_JLE: FlagState = new z3::expr(**get_flag_expr(state, FLAG_SF) != **get_flag_expr(state, FLAG_OF)); break;

				case ZYDIS_MNEMONIC_JNO: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_OF)); break;
				case ZYDIS_MNEMONIC_JO: FlagState = new z3::expr(**get_flag_expr(state, FLAG_OF)); break;

				case ZYDIS_MNEMONIC_JNP: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_PF)); break;
				case ZYDIS_MNEMONIC_JP: FlagState = new z3::expr(**get_flag_expr(state, FLAG_PF)); break;

				case ZYDIS_MNEMONIC_JNS: FlagState = new z3::expr(!**get_flag_expr(state, FLAG_SF)); break;
				case ZYDIS_MNEMONIC_JS: FlagState = new z3::expr(**get_flag_expr(state, FLAG_SF)); break;
				}
				if (FlagState != nullptr)
				{
					z3::solver s1(z3c);
					s1.add(*FlagState);
					if (s1.check() == z3::unsat) return ObjOpaque_predicate.opaque_predicate_not_taken;

					z3::solver s2(z3c);
					s2.add(!*FlagState);
					if (s2.check() == z3::unsat) return ObjOpaque_predicate.opaque_predicate_taken;

					return ObjOpaque_predicate.not_opaque_predicate;
				}
				return ObjOpaque_predicate.error_opaque_predicate;
			}
		}

		static inline opaque_predicate::opaque_predicate_ is_opaque_predicate(
			uc_engine* uc,
			bool FirstPhaseInProcess,
			std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode)
		{
			if (FirstPhaseInProcess == false)
			{
				state.create_initial_state(z3c, state);
			}
			for (auto& OpaquePredicateCodeIter : OpaquePredicateCode)
			{
				AsmX64InstrsTranslate::InstructionChooser(uc, z3c, OpaquePredicateCodeIter, state);
			}
			//FirstPhaseInProcess = true;
			return FlagInOpaquePredicate::ConditionCheck(z3c, state, OpaquePredicateCode[OpaquePredicateCode.size() - 1]);
		}
	}

	static inline void OpaquePredicateRemoverInit(
		uc_engine* uc,
		ZydisDisassembledInstruction& instruction,
		bool FirstPhaseInProcess,
		std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode)
	{
		ZydisDisassembledInstruction jcc_instr = OpaquePredicateCode[OpaquePredicateCode.size() - 1];

		std::cout << (jcc_instr.text) << ". instruction is conditional " << std::endl;
		std::cout << " > testing: " << jcc_instr.text << std::endl;

		opaque_predicate::opaque_predicate_ result = OpaquePredicate::is_opaque_predicate(uc, FirstPhaseInProcess,OpaquePredicateCode);

		switch (result)
		{
		case ObjOpaque_predicate.not_opaque_predicate:
			std::cout << "not an opaque predicate" << std::endl;
			break;
		case ObjOpaque_predicate.opaque_predicate_taken:
			std::cout << "opaque predicate: always taken" << std::endl;
			OpaquePredicateCode.erase(OpaquePredicateCode.end()-1);
			OpaquePredicateCode.erase(OpaquePredicateCode.end()-1);
			break;
		case ObjOpaque_predicate.opaque_predicate_not_taken:
			std::cout << "opaque predicate: never taken" << std::endl;
			OpaquePredicateCode.erase(OpaquePredicateCode.end()-1);
			OpaquePredicateCode.erase(OpaquePredicateCode.end()-1);
			break;
		case ObjOpaque_predicate.error_opaque_predicate:
			std::cout << "opaque predicate: error" << std::endl;
			break;
		}
	}

	void OpaquePredicateRemover(
		uc_engine* uc,
		uint64_t address,
		ZydisDisassembledInstruction& instruction,
		std::vector<ZydisDisassembledInstruction>& SourceOpaquePredicateCode,
		std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode,
		std::vector<ZyanU8>& Data,
		bool FirstPhaseInProcess)
	{
		std::unordered_set<ZydisMnemonic> JccMnemonics{
			 ZYDIS_MNEMONIC_JNBE, ZYDIS_MNEMONIC_JNB, ZYDIS_MNEMONIC_JB,
			 ZYDIS_MNEMONIC_JBE, ZYDIS_MNEMONIC_JZ, ZYDIS_MNEMONIC_JNLE,
			 ZYDIS_MNEMONIC_JNL, ZYDIS_MNEMONIC_JL, ZYDIS_MNEMONIC_JLE,
			 ZYDIS_MNEMONIC_JNZ, ZYDIS_MNEMONIC_JNO, ZYDIS_MNEMONIC_JNP,
			 ZYDIS_MNEMONIC_JNS, ZYDIS_MNEMONIC_JO, ZYDIS_MNEMONIC_JP,
			 ZYDIS_MNEMONIC_JS };

		OpaquePredicateCode.push_back(instruction);
		SourceOpaquePredicateCode.push_back(instruction);

		if (JccMnemonics.count(instruction.info.mnemonic) != 0)
		{
			OpaquePredicateRemoverInit(uc, instruction, FirstPhaseInProcess, OpaquePredicateCode);
		}

		/*
		for (std::vector<ZydisMnemonic>::iterator::value_type& JccMnemonicsIter : JccMnemonics)
		{
			if (instruction.info.mnemonic == JccMnemonicsIter)
			{
				return OpaquePredicateRemoverInit(uc, instruction, FirstPhaseInProcess, OpaquePredicateCode);
			}
		}
		*/

		if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			PhasePatcher::UcPhasePatcher(uc, SourceOpaquePredicateCode, OpaquePredicateCode,Data);
			/*
			unsigned char NOP = 0x90;

			for (auto& SourceOpaquePredicateCodeIter : SourceOpaquePredicateCode)
			{
				uc_mem_write(uc, SourceOpaquePredicateCodeIter.runtime_address, &NOP, SourceOpaquePredicateCodeIter.info.length);
			}
			SourceOpaquePredicateCode.clear();

			ZydisEncoderRequest EncInstr;
			memset(&EncInstr, 0, sizeof(EncInstr));

			for (auto& OpaquePredicateCodeIter : OpaquePredicateCode)
			{
				std::unordered_set<ZyanU8> RelativeInstr(OpaquePredicateCodeIter.info.operand_count);

				EncInstr.mnemonic = OpaquePredicateCodeIter.info.mnemonic;
				EncInstr.machine_mode = OpaquePredicateCodeIter.info.machine_mode;
				EncInstr.operand_count = OpaquePredicateCodeIter.info.operand_count;

				std::vector<ZyanU8> encoded_instruction(ZYDIS_MAX_INSTRUCTION_LENGTH); 
				ZyanUSize encoded_length = ZYDIS_MAX_INSTRUCTION_LENGTH;

				for (size_t OpNum = 0; OpNum <= OpaquePredicateCodeIter.info.operand_count; OpNum++)
				{
					switch (OpaquePredicateCodeIter.operands[OpNum].type)
					{
					case ZYDIS_OPERAND_TYPE_REGISTER:
						EncInstr.operands[OpNum].type = OpaquePredicateCodeIter.operands[OpNum].type;
						EncInstr.operands[OpNum].reg.value = OpaquePredicateCodeIter.operands[OpNum].reg.value;
						break;
					case ZYDIS_OPERAND_TYPE_IMMEDIATE:
						EncInstr.operands[OpNum].type = OpaquePredicateCodeIter.operands[OpNum].type;
						if (OpaquePredicateCodeIter.operands[OpNum].imm.is_relative == ZyanBool(true))
						{
							ZydisDecodedInstruction Instruction; const ZyanUSize length = Data.size();
							ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]; ZydisDecoder decoder;
							ZyanU64 result_address = 0; 

							ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

							ZydisDecoderDecodeFull(&decoder, &Data, length,
								&Instruction, operands);

							ZydisCalcAbsoluteAddress(&Instruction, &operands[OpNum], (ZyanU64)OpaquePredicateCodeIter.runtime_address, &result_address);

							EncInstr.operands[OpNum].imm.u = result_address;
							break;
						}
						EncInstr.operands[OpNum].imm.u = OpaquePredicateCodeIter.operands[OpNum].imm.value.u;
						break;
					case ZYDIS_OPERAND_TYPE_MEMORY:
						EncInstr.operands[OpNum].type = OpaquePredicateCodeIter.operands[OpNum].type;
						EncInstr.operands[OpNum].ptr.segment = OpaquePredicateCodeIter.operands[OpNum].ptr.segment;
						if (OpaquePredicateCodeIter.operands[OpNum].mem.base != ZYDIS_REGISTER_NONE)
						{
							EncInstr.operands[OpNum].mem.base = OpaquePredicateCodeIter.operands[OpNum].mem.base;
						}
						if (OpaquePredicateCodeIter.operands[OpNum].mem.index != ZYDIS_REGISTER_NONE)
						{
							EncInstr.operands[OpNum].mem.index = OpaquePredicateCodeIter.operands[OpNum].mem.index;
						}
						if (OpaquePredicateCodeIter.operands[OpNum].mem.scale != 0)
						{
							EncInstr.operands[OpNum].mem.scale = OpaquePredicateCodeIter.operands[OpNum].mem.scale;
						}
						if (OpaquePredicateCodeIter.operands[OpNum].mem.disp.has_displacement == ZyanBool(true))
						{
							EncInstr.operands[OpNum].mem.displacement = OpaquePredicateCodeIter.operands[OpNum].mem.disp.value;
						}
						break;
					default:
						break;
					}
				}

				if (RelativeInstr.count(true) != 0)
				{
					ZydisEncoderEncodeInstructionAbsolute(&EncInstr, &encoded_instruction, &encoded_length, (ZyanU64)OpaquePredicateCodeIter.runtime_address);
					//uc_mem_write(uc, OpaquePredicateCodeIter.runtime_address, &NOP, encoded_length);

					uc_mem_write(uc, OpaquePredicateCodeIter.runtime_address, &encoded_instruction, encoded_length);
				}
				else
				{
					ZydisEncoderEncodeInstruction(&EncInstr, &encoded_instruction, &encoded_length);
					//uc_mem_write(uc, OpaquePredicateCodeIter.runtime_address, &NOP, encoded_length);

					uc_mem_write(uc, OpaquePredicateCodeIter.runtime_address, &encoded_instruction, encoded_length);
				}
			}
			OpaquePredicateCode.clear();
			*/
		}
	}
}