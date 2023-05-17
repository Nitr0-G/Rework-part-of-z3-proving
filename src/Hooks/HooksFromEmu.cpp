#include "HooksFromEmu.hpp"
#include "Phases/FirstPhase.hpp"
#include "Phases/SecondPhase.hpp"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <immintrin.h>
#include <intrin.h>
#include <filesystem>
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <cstdio>
#include <strsafe.h>
#include <list>
#include <string>
#include <queue>
#include <fstream>
#include <iostream>

class HookCode_ {
public:
	bool FirstPhaseInProcess = false, FirstPhaseDone = false;
	std::vector<ZydisDisassembledInstruction> OpaquePredicateCode;
public:
	bool SecondPhaseInProcess = false, SecondPhaseDone = false;
	std::vector<ZydisDisassembledInstruction> DeadCode;
};

namespace Hooks 
{
	void HookMemWrite(
		uc_engine* uc, 
		uint64_t address, 
		uint32_t size) 
	{
	
	}

	void HookMemRead(
		uc_engine* uc, 
		uint64_t address, 
		uint32_t size) 
	{
	
	}

	void HookCode(
		uc_engine* uc,
		uint64_t address,
		uint32_t size,
		void* user_data)
	{	
		std::vector<ZyanU8> Data(size);
		uc_mem_read(uc, address, Data.data(), size);
		const ZyanUSize length = Data.size();
		ZydisDisassembledInstruction instruction;
		if (ZYAN_SUCCESS(ZydisDisassembleIntel(
			ZYDIS_MACHINE_MODE_LONG_64, address, Data.data(), length, &instruction)))
		{
			if (instruction.info.mnemonic != ZYDIS_MNEMONIC_JMP)
			{
				std::cout << ">>> INSTR = " << instruction.text << "\n\n";
				HookCode_* HookCode = static_cast<HookCode_*>(user_data);
				if (HookCode->FirstPhaseDone == false)
				{
					FirstPhase::OpaquePredicateRemover(uc, instruction, HookCode->OpaquePredicateCode, Data, HookCode->FirstPhaseInProcess);
					return;
				}
				else if (HookCode->SecondPhaseDone == false)
				{
					if (instruction.info.mnemonic != ZYDIS_MNEMONIC_CALL)
					{
						HookCode->DeadCode.push_back(instruction);
						return;
					}
					SecondPhase::DeadCodeEleminator(uc, instruction, HookCode->DeadCode, HookCode->SecondPhaseInProcess);
					return;
				}
				return;
			}
			else
			{
				return;
			}
		}
		return;
	}

	void HookBlock(
		uc_engine* uc,
		uint64_t address,
		uint32_t size) 
	{

	}
}