#pragma once

#include <Zydis/Zydis.h>
#include <vector>

namespace FirstPhase {

	void OpaquePredicateRemover(
		ZydisDisassembledInstruction& instruction,
		std::vector<ZydisDisassembledInstruction>& OpaquePredicateCode,
		std::vector<ZyanU8>& Data,
		bool FirstPhaseInProcess);
}