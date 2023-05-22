#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <vector>
#include <string>
#include <iostream>
#include <unordered_set>

namespace PhasePatcher {

	void UcPhasePatcher(
		uc_engine* UnicornHandle,
		std::vector<ZydisDisassembledInstruction> SourceCode,
		std::vector<ZydisDisassembledInstruction> TargetCode,
		std::vector<ZyanU8> OpcodesOfInstrs);
}