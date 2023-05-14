#pragma once

#include <unicorn/unicorn.h>

#include <vector>
#include <WTypesbase.h>
#include <string>

class LoaderEmu;

namespace PeLoaderEmu 
{
	LoaderEmu WorkWithPe(
		const std::string& lpFilePath,
		const std::string& lpFilePathWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe);

	LoaderEmu SectionAllocation64(
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_SECTION_HEADER pImageSectionHeader,
		const PIMAGE_NT_HEADERS64 pImageNTHeader64,
		const int NumberOfSections,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe);

	LoaderEmu SectionAllocation32(
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_SECTION_HEADER pImageSectionHeader,
		const PIMAGE_NT_HEADERS32 pImageNTHeader32,
		const int NumberOfSections,
		uc_engine* uc,
		LoaderEmu& EmuLoader);

	LoaderEmu PeInit(
		const std::string& lpFilePathWithName, 
		LoaderEmu& EmuLoader);
};

namespace DllLoaderEmu 
{
	LoaderEmu WorkWithDll(
		const std::string& DllName,
		const std::string& lpPathToDllWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe);
}