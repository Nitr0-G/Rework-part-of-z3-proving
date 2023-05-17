#include "PeLoaderEmu.hpp"
#include "Emu.hpp"
#include "HooksFromEmu.hpp"

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
#include <Psapi.h>
#include <string>
#include <queue>
#include <fstream>
#include <iostream>

class LoaderEmu {
public:
	uc_mode BitMode = uc_mode(0);
public:
	std::vector<uint64_t> svSizes;
	std::vector<uint64_t> svAOfSections;
	std::vector<LPVOID> svBAOfSections;
public:
	HANDLE hFileContent = INVALID_HANDLE_VALUE;
	HANDLE hPeFileContent = INVALID_HANDLE_VALUE;
public:
	PIMAGE_DOS_HEADER pImageDOSHeaderOfPe = nullptr;
	PIMAGE_NT_HEADERS pImageNTHeaderOfPe = nullptr;
public:
	uint64_t EP = 0;
	uint64_t SizeOfStack = 0x1000;
public:
	unsigned int Counter = 0;
};

class Registers {
public:
	const uint32_t AlignNumber = 0x1000;
	const uint64_t stack_address = 0x10000;
	const uint64_t gs_address = 0x22A000;
	const uint64_t es_address = 0x22D000;
	const uint64_t cs_address = 0x230000;
	const uint64_t fs_address = 0x233000;
public:
	uint64_t RSP = stack_address + AlignNumber;
	uint64_t GS = gs_address + AlignNumber;
	uint64_t ES = es_address + AlignNumber;
	uint64_t CS = cs_address + AlignNumber;
	uint64_t FS = fs_address + AlignNumber;
public:
	std::vector<uint64_t> svGeneralPurposeUcRegisters = {
		0x0,//1
		0x0,//2
		0x0,//3
		0x0,//4
		0x0,//5
		0x0,//6
		0x0,//7
		0x0,//8
		0x0,//9
		0x0,//10
		0x0,//11
		0x0,//12
		0x0,//13
		0x0,//14
		0x0,//15
		0x0,//16
		0x0}; // 17

	const std::vector<uc_x86_reg> GeneralPurposeUcRegs{
		UC_X86_REG_RAX,//1
		UC_X86_REG_RBX,//2
		UC_X86_REG_RCX,//3
		UC_X86_REG_RDX,//4
		UC_X86_REG_RSI,//5
		UC_X86_REG_RDI,//6
		UC_X86_REG_R8,//7
		UC_X86_REG_R9,//8
		UC_X86_REG_R10,//9
		UC_X86_REG_R11,//10
		UC_X86_REG_R12,//11
		UC_X86_REG_R13,//12
		UC_X86_REG_R14,//13
		UC_X86_REG_R15,//14
		UC_X86_REG_RFLAGS,//15
		UC_X86_REG_RBP,//16
		UC_X86_REG_RIP}; // 17

	std::vector<__m128> svXmmUcRegisters{
		_mm_setzero_ps(),//1
		_mm_setzero_ps(),//2
		_mm_setzero_ps(),//3
		_mm_setzero_ps(),//4
		_mm_setzero_ps(),//5
		_mm_setzero_ps(),//6
		_mm_setzero_ps(),//7
		_mm_setzero_ps(),//8
		_mm_setzero_ps(),//9
		_mm_setzero_ps(),//10
		_mm_setzero_ps(),//11
		_mm_setzero_ps(),//12
		_mm_setzero_ps(),//13
		_mm_setzero_ps(),//14
		_mm_setzero_ps(),//15
		_mm_setzero_ps(),//16

	};

	const std::vector<uc_x86_reg> XmmUcRegs{
		UC_X86_REG_XMM0,
		UC_X86_REG_XMM1,
		UC_X86_REG_XMM2,
		UC_X86_REG_XMM3,
		UC_X86_REG_XMM4,
		UC_X86_REG_XMM5,
		UC_X86_REG_XMM6,
		UC_X86_REG_XMM7,
		UC_X86_REG_XMM8,
		UC_X86_REG_XMM9,
		UC_X86_REG_XMM10,
		UC_X86_REG_XMM11,
		UC_X86_REG_XMM12,
		UC_X86_REG_XMM13,
		UC_X86_REG_XMM14,
		UC_X86_REG_XMM15};
};

class HookCode_ {
public:
	bool FirstPhaseInProcess = false, FirstPhaseDone = false;
	std::vector<ZydisDisassembledInstruction> OpaquePredicateCode;
public:
	bool SecondPhaseInProcess = false, SecondPhaseDone = false;
	std::vector<ZydisDisassembledInstruction> DeadCode;
};

namespace Emu
{
	int PhasesCounter;
	static inline void UcRegsInit(
		LoaderEmu& EmuLoader,
		Registers& Registers,
		uc_err err, 
		uc_engine* uc) 
	{
		err = uc_reg_write(uc, UC_X86_REG_RSP, &Registers.RSP);
		err = uc_reg_write(uc, UC_X86_REG_GS_BASE, &Registers.GS);
		err = uc_reg_write(uc, UC_X86_REG_ES, &Registers.ES);
		err = uc_reg_write(uc, UC_X86_REG_CS, &Registers.CS);
		err = uc_reg_write(uc, UC_X86_REG_FS_BASE, &Registers.FS);

		for (size_t size = 0; size < Registers.svGeneralPurposeUcRegisters.size(); size++)
		{
			err = uc_reg_write(uc, Registers.GeneralPurposeUcRegs[size], &Registers.svGeneralPurposeUcRegisters[size]);
		}

		for (size_t size = 0; size < Registers.svXmmUcRegisters.size(); size++)
		{
			err = uc_reg_write(uc, Registers.XmmUcRegs[size], &Registers.svXmmUcRegisters[size]);
		}
	}

	static inline void SectionMappingForUc(
		const LoaderEmu& EmuLoader, 
		Registers& Registers,
		uc_err err,
		uc_engine* uc)
	{
		err = uc_mem_map(uc, Registers.stack_address, EmuLoader.SizeOfStack, UC_PROT_ALL);

		err = uc_mem_map(uc, Registers.gs_address, 0x1000, UC_PROT_ALL);
		err = uc_mem_map(uc, Registers.es_address, 0x1000, UC_PROT_ALL);
		err = uc_mem_map(uc, Registers.cs_address, 0x1000, UC_PROT_ALL);
		err = uc_mem_map(uc, Registers.fs_address, 0x1000, UC_PROT_ALL);
	};

	static inline int EmuStart(
		uc_engine* uc,
		HookCode_& HookCode,
		LoaderEmu EmuLoader,
		uint64_t SizeOfAll,
		uc_err err)
	{
		++PhasesCounter;

		err = uc_emu_start(uc, EmuLoader.EP, EmuLoader.EP + SizeOfAll, 0, 17);
		if (err)
		{
			uint64_t RSP, RIP;
			printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
			uc_reg_read(uc, UC_X86_REG_RSP, &RSP); uc_reg_read(uc, UC_X86_REG_RIP, &RIP);
			std::cout << std::hex << RSP << "\n\n"; std::cout << std::hex << RIP;
		}
		if (PhasesCounter == 1)
		{
			HookCode.FirstPhaseDone = true;

			system("cls");

			std::cout << "The second phase" << "\n\n";
			EmuStart(uc, HookCode, EmuLoader, SizeOfAll, err);
		}
		else if (PhasesCounter == 2)
		{
			HookCode.SecondPhaseDone = true;

			system("cls");

			std::cout << "The third phase" << "\n\n";
			EmuStart(uc, HookCode, EmuLoader, SizeOfAll, err);
		}
		else if (PhasesCounter == 5)
		{
			return 0;
		}
		return 0;
	}

	int UcStartUp(
		std::string& lpFilePathWithName) 
	{
		std::string FileName;
		std::string FileExt;
		LoaderEmu EmuLoader;
		Registers Registers;
		HookCode_ HookCode;
		uc_hook hook_block_ = 0;
		uc_hook hook_code_ = 0;
		uc_hook hook_mem_read = 0;
		uc_hook hook_mem_write = 0;
		uc_engine* uc = nullptr;
		uc_err err{};
		uint64_t SizeOfAll = 0;

		EmuLoader = PeLoaderEmu::PeInit(lpFilePathWithName, EmuLoader);

		err = uc_open(UC_ARCH_X86, EmuLoader.BitMode, &uc);
		if (err != UC_ERR_OK)
		{
			printf("Failed to initialize Unicorn engine: %s\n", uc_strerror(err));
			return -1;
		}

		std::filesystem::path pwn(lpFilePathWithName.c_str());

		EmuLoader = PeLoaderEmu::WorkWithPe((const std::string&)pwn.parent_path(), lpFilePathWithName, uc, EmuLoader, (std::string&)pwn.filename());

		SectionMappingForUc(EmuLoader, Registers, err, uc);

		UcRegsInit(EmuLoader, Registers, err, uc);

		uc_hook_add(uc, &hook_code_, UC_HOOK_CODE, Hooks::HookCode, &HookCode, 1, 0);
		uc_hook_add(uc, &hook_block_, UC_HOOK_BLOCK, Hooks::HookBlock, NULL, 1, 0);
		uc_hook_add(uc, &hook_mem_read, UC_HOOK_MEM_READ, Hooks::HookMemRead, NULL, 1, 0);
		uc_hook_add(uc, &hook_mem_write, UC_HOOK_MEM_WRITE, Hooks::HookMemWrite, NULL, 1, 0);

		for (int i = 0; i < EmuLoader.Counter; i++)
		{
			SizeOfAll =+ EmuLoader.svSizes[i];
		}
		EmuStart(uc, HookCode, EmuLoader, SizeOfAll, err);
		/*
		err = uc_emu_start(uc, EmuLoader.EP, EmuLoader.EP + SizeOfAll, 0, 12);
		if (err)
		{
			uint64_t RSP, RIP;
			printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
			uc_reg_read(uc, UC_X86_REG_RSP, &RSP); uc_reg_read(uc, UC_X86_REG_RIP, &RIP);
			std::cout << std::hex << RSP << "\n\n"; std::cout << std::hex << RIP;
		}
		if (PhasesCounter == 1)
		{
			HookCode.FirstPhaseDone = true;

			system("cls");



			std::cout << "The second phase" << "\n\n";
			UcStartUp(lpFilePathWithName);
		}
		else if (PhasesCounter == 2)
		{
			HookCode.SecondPhaseDone = true;

			system("cls");

			std::cout << "The third phase" << "\n\n";
			UcStartUp(lpFilePathWithName);
		}
		else if (PhasesCounter == 5)
		{
			return 0;
		}
		*/
		return 0;
	}
}