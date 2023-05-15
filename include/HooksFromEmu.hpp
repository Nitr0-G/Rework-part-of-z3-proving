#pragma once
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

namespace Hooks 
{
	void HookMemWrite(
		uc_engine* uc, 
		uint64_t address, 
		uint32_t size);

	void HookMemRead(
		uc_engine* uc, 
		uint64_t address, 
		uint32_t size);

	void HookCode(
		uc_engine* uc, 
		uint64_t address, 
		uint32_t size, 
		void* user_data);

	void HookBlock(
		uc_engine* uc, 
		uint64_t address, 
		uint32_t size);
}