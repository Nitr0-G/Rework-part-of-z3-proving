#include "Phases/PhasePatcher.hpp"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <vector>
#include <string>
#include <iostream>
#include <unordered_set>

namespace PhasePatcher {

	static inline int  UcCacheRemover(
		uc_engine* UnicornHandle,
		uint64_t address)
	{
		uc_tb TranslationBlock;
		if (uc_ctl_request_cache(UnicornHandle, address, &TranslationBlock) != UC_ERR_OK)
		{
			printf("Failed on uc_ctl_request_cache()\n");
			return 0;
		}
		if (uc_ctl_remove_cache(UnicornHandle, TranslationBlock.pc, TranslationBlock.pc + TranslationBlock.size) != UC_ERR_OK)
		{
			printf("Failed on uc_ctl_remove_cache()\n");
			return 0;
		}
		return 1;
	}

	void UcPhasePatcher(
		uc_engine* UnicornHandle,
		std::vector<ZydisDisassembledInstruction> SourceCode,
		std::vector<ZydisDisassembledInstruction> TargetCode,
		std::vector<ZyanU8> OpcodesOfInstrs)
	{
		unsigned char NOP = 0x90;

		for (auto& SourceOpaquePredicateCodeIter : SourceCode)
		{
			for (size_t size = 0; size < SourceOpaquePredicateCodeIter.info.length; ++size)
			{
				uc_mem_write(UnicornHandle, SourceOpaquePredicateCodeIter.runtime_address + size, &NOP, 1);
			}
		}

		SourceCode.clear();

		ZydisEncoderRequest EncInstr;

		for (auto& OpaquePredicateCodeIter : TargetCode)
		{
			memset(&EncInstr, 0, sizeof(EncInstr));
			std::unordered_set<ZyanU8> RelativeInstr(OpaquePredicateCodeIter.info.operand_count);

			EncInstr.mnemonic = OpaquePredicateCodeIter.info.mnemonic;
			EncInstr.machine_mode = OpaquePredicateCodeIter.info.machine_mode;
			EncInstr.operand_count = OpaquePredicateCodeIter.info.operand_count_visible;

		//	RelativeInstr.insert(true);

		//	EncInstr.mnemonic = ZYDIS_MNEMONIC_CALL;
		//	EncInstr.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
		//	EncInstr.operand_count = 1;
			
		//	EncInstr.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
		//	EncInstr.operands[0].mem.base = ZYDIS_REGISTER_RIP;
		//	EncInstr.operands[0].mem.index = ZYDIS_REGISTER_NONE;
		//	EncInstr.operands[0].mem.scale = 0;
		//	EncInstr.operands[0].mem.size = 8;
		//	EncInstr.operands[0].mem.displacement = 0x0000000140002010;
			// 
			//EncInstr.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
			//EncInstr.operands[0].reg.value = ZYDIS_REGISTER_RAX;
			//EncInstr.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			//EncInstr.operands[1].imm.u = 0x1;

			ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH];
			ZyanUSize encoded_length = sizeof(encoded_instruction);

			
			for (size_t OpNum = 0; OpNum < OpaquePredicateCodeIter.info.operand_count_visible; OpNum++)
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
						RelativeInstr.insert(true);
						ZydisDecodedInstruction Instruction; const ZyanUSize length = OpcodesOfInstrs.size();
						ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]; ZydisDecoder decoder;
						ZyanU64 result_address = 0;

						ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

						ZydisDecoderDecodeFull(&decoder, &OpcodesOfInstrs, length,
							&Instruction, operands);

						ZydisCalcAbsoluteAddress(&Instruction, &operands[OpNum], (ZyanU64)OpaquePredicateCodeIter.runtime_address, &result_address);

						EncInstr.operands[OpNum].imm.u = result_address;
						break;
					}
					EncInstr.operands[OpNum].imm.u = OpaquePredicateCodeIter.operands[OpNum].imm.value.u;
					break;
				case ZYDIS_OPERAND_TYPE_MEMORY:
					EncInstr.operands[OpNum].type = OpaquePredicateCodeIter.operands[OpNum].type;
					//EncInstr.operands[OpNum].ptr.segment = OpaquePredicateCodeIter.operands[OpNum].ptr.segment;
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
					if (OpaquePredicateCodeIter.operands[OpNum].element_size == 64)
					{
						EncInstr.operands[0].mem.size = 8;
					}
					else if (OpaquePredicateCodeIter.operands[OpNum].element_size == 32)
					{
						EncInstr.operands[0].mem.size = 4;
					}
					else if (OpaquePredicateCodeIter.operands[OpNum].element_size == 16)
					{
						EncInstr.operands[0].mem.size = 2;
					}
					else if (OpaquePredicateCodeIter.operands[OpNum].element_size == 8)
					{
						EncInstr.operands[0].mem.size = 1;
					}
					if (OpaquePredicateCodeIter.operands[OpNum].mem.disp.has_displacement == ZyanBool(true))
					{
						if (OpaquePredicateCodeIter.operands[OpNum].mem.base == ZYDIS_REGISTER_RIP)
						{
							RelativeInstr.insert(true);

							EncInstr.operands[OpNum].mem.displacement 
								= OpaquePredicateCodeIter.runtime_address + OpaquePredicateCodeIter.operands[OpNum].mem.disp.value +
								OpaquePredicateCodeIter.info.length;

							//EncInstr.operands[OpNum].mem.displacement = OpaquePredicateCodeIter.operands[OpNum].mem.disp.value;

							break;
						}

						EncInstr.operands[OpNum].mem.displacement = OpaquePredicateCodeIter.operands[OpNum].mem.disp.value;
						
					}
					break;
				default:
					break;
				}
			}
			
	
			if (RelativeInstr.count(true) != 0)
			{
				ZydisEncoderEncodeInstructionAbsolute(&EncInstr, encoded_instruction, &encoded_length, (ZyanU64)OpaquePredicateCodeIter.runtime_address);

				uc_mem_write(UnicornHandle, OpaquePredicateCodeIter.runtime_address, &encoded_instruction, encoded_length);
			}
			else
			{
				ZydisEncoderEncodeInstruction(&EncInstr, encoded_instruction, &encoded_length);

				uc_mem_write(UnicornHandle, OpaquePredicateCodeIter.runtime_address, &encoded_instruction, encoded_length);
			}
			

			if (UcCacheRemover(UnicornHandle, OpaquePredicateCodeIter.runtime_address) != 1)
			{
				printf("Error in UcCacheRemover - fatal exit");
			}
			
			std::fill_n(encoded_instruction, sizeof(encoded_instruction), 0);
		}
		TargetCode.clear();
	}
}