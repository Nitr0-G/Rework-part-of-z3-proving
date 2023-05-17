#pragma once

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <vector>
#include <list>

namespace SecondPhase {

	void DeadCodeEleminator(
		uc_engine* uc,
		ZydisDisassembledInstruction& instruction,
		std::vector<ZydisDisassembledInstruction>& DeadCode,
		bool SecondPhaseInProcess);
}