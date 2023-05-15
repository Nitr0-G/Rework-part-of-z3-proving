#include "Phases/FirstPhase.hpp"
#include "z3/z3states.hpp"
#include "z3/z3ASMx64Instructions.hpp"

#include <Zydis/Zydis.h>
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
			bool FirstPhaseInProcess,
			std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode)
		{
			if (FirstPhaseInProcess == false)
			{
				//x8664_ctx state; x8664_ctx new_state;
				//z3::context z3c;

				state.create_initial_state(z3c, state);
			}
			for (auto& OpaquePredicateCodeIter : OpaquePredicateCode)
			{
				AsmX64InstrsTranslate::InstructionChooser(z3c, OpaquePredicateCodeIter, state);
			}
			FirstPhaseInProcess = true;
			return FlagInOpaquePredicate::ConditionCheck(z3c, state, OpaquePredicateCode[OpaquePredicateCode.size() - 1]);
		}
	}

	static inline void OpaquePredicateRemoverInit(
		ZydisDisassembledInstruction& instruction,
		bool FirstPhaseInProcess,
		std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode)
	{
		ZydisDisassembledInstruction jcc_instr = OpaquePredicateCode[OpaquePredicateCode.size() - 1];

		std::cout << (jcc_instr.text) << ". instruction is conditional " << std::endl;
		std::cout << " > testing: " << jcc_instr.text << std::endl;

		opaque_predicate::opaque_predicate_ result = OpaquePredicate::is_opaque_predicate(FirstPhaseInProcess,OpaquePredicateCode);

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
		ZydisDisassembledInstruction& instruction,
		std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode,
		std::vector<ZyanU8>& Data,
		bool FirstPhaseInProcess,
		bool FirstPhaseDone)
	{
        std::vector<ZydisMnemonic>JccMnemonics{
			ZYDIS_MNEMONIC_JNBE, ZYDIS_MNEMONIC_JNB, ZYDIS_MNEMONIC_JB,
			ZYDIS_MNEMONIC_JBE, ZYDIS_MNEMONIC_JZ, ZYDIS_MNEMONIC_JNLE,
			ZYDIS_MNEMONIC_JNL, ZYDIS_MNEMONIC_JL, ZYDIS_MNEMONIC_JLE,
			ZYDIS_MNEMONIC_JNZ, ZYDIS_MNEMONIC_JNO, ZYDIS_MNEMONIC_JNP,
			ZYDIS_MNEMONIC_JNS, ZYDIS_MNEMONIC_JO, ZYDIS_MNEMONIC_JP,
			ZYDIS_MNEMONIC_JS };

		OpaquePredicateCode.push_back(instruction);

		for (std::vector<ZydisMnemonic>::iterator::value_type& JccMnemonicsIter : JccMnemonics)
		{
			if (instruction.info.mnemonic == JccMnemonicsIter)
			{
				return OpaquePredicateRemoverInit(instruction, FirstPhaseInProcess, OpaquePredicateCode);
			}
		}
	}
}