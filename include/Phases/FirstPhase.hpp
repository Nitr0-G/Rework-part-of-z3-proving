#pragma once

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <vector>

namespace FirstPhase {

	void OpaquePredicateRemover(
		uc_engine* uc,
		ZydisDisassembledInstruction& instruction,
		std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode,
		std::vector<ZyanU8>& Data,
		bool FirstPhaseInProcess);
}