#include "PeLoaderEmu.hpp"

#include <immintrin.h>
#include <string_view>
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <cstdio>
#include <strsafe.h>
#include <Psapi.h>

extern std::vector<std::string> SectionNames;

class LoaderEmu {
public:

	uc_mode BitMode;
	std::vector<uint64_t> svSizes;
	std::vector<uint64_t> svAOfSections;
	std::vector<LPVOID> svBAOfSections;
	HANDLE hFileContent;
	HANDLE hPeFileContent;
	PIMAGE_DOS_HEADER pImageDOSHeaderOfPe;
	PIMAGE_NT_HEADERS pImageNTHeaderOfPe;
	uint64_t EP;
	uint64_t SizeOfStack = 0x1000;
	unsigned int Counter = 0;
};

std::wstring StringToWideString(
	const std::string& str)
{
	// Create a std::string_view from the input string
	std::string_view strView(str);

	// Create a std::wstring from the std::string_view using the data() function
	std::wstring wideStr(strView.data(), strView.data() + strView.size());

	return wideStr;
}

namespace DllLoaderEmu 
{
	LoaderEmu ParseImageOfDll64(
		PIMAGE_DOS_HEADER pImageDOSHeader,
		const std::string& DllName,
		const std::string& lpPathToDllWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe)
	{
		const PIMAGE_NT_HEADERS64 pImageNTHeader64 =
			(PIMAGE_NT_HEADERS64)((DWORD_PTR)pImageDOSHeader + pImageDOSHeader->e_lfanew);
		if (pImageNTHeader64 == nullptr)
		{
			return EmuLoader;
		}

		const IMAGE_FILE_HEADER ImageFileHeader = pImageNTHeader64->FileHeader;
		const IMAGE_OPTIONAL_HEADER64 ImageOptionalHeader64 = pImageNTHeader64->OptionalHeader;

		const PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + ImageFileHeader.SizeOfOptionalHeader);
		if (pImageSectionHeader == nullptr)
		{
			return EmuLoader;
		}

		EmuLoader = PeLoaderEmu::SectionAllocation64(
			pImageDOSHeader,
			pImageSectionHeader,
			pImageNTHeader64,
			ImageFileHeader.NumberOfSections,
			uc,
			EmuLoader,
			NameOfExe);

		return EmuLoader;
	}

	LoaderEmu ParseImageOfDll32(
		PIMAGE_DOS_HEADER pImageDOSHeader,
		const std::string& DllName,
		const std::string& lpPathToDllWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader)
	{
		const PIMAGE_NT_HEADERS32 pImageNTHeader32 =
			(PIMAGE_NT_HEADERS32)((DWORD_PTR)pImageDOSHeader + pImageDOSHeader->e_lfanew);
		if (pImageNTHeader32 == nullptr)
		{
			return EmuLoader;
		}

		const IMAGE_FILE_HEADER ImageFileHeader = pImageNTHeader32->FileHeader;
		const IMAGE_OPTIONAL_HEADER32 ImageOptionalHeader32 = pImageNTHeader32->OptionalHeader;

		const PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + ImageFileHeader.SizeOfOptionalHeader);
		if (pImageSectionHeader == nullptr)
		{
			return EmuLoader;
		}

		EmuLoader = PeLoaderEmu::SectionAllocation32(
			pImageDOSHeader,
			pImageSectionHeader,
			pImageNTHeader32,
			ImageFileHeader.NumberOfSections,
			uc,
			EmuLoader);

		return EmuLoader;
	}

	HANDLE GetContentOfDll(
		const std::wstring& DllName, 
		LoaderEmu& EmuLoader)
	{
		const HMODULE hFile = LoadLibraryW(DllName.c_str());
		if (hFile == 0)
		{
			printf("[-] An error occured when trying to open the PE file !");
			return nullptr;
		}
		return hFile;
	}

	LoaderEmu WorkWithDll(
		const std::string& DllName,
		const std::string& lpPathToDllWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe)
	{
		EmuLoader.hFileContent = GetContentOfDll(StringToWideString(DllName), EmuLoader);
		if (EmuLoader.hFileContent == 0)
		{
			if (EmuLoader.hFileContent != nullptr)
			{
				CloseHandle(EmuLoader.hFileContent);
			}
			return EmuLoader;
		}

		const auto pImageDOSHeader = (PIMAGE_DOS_HEADER)EmuLoader.hFileContent;
		if (pImageDOSHeader == nullptr)
		{
			if (EmuLoader.hFileContent != nullptr)
			{
				HeapFree(EmuLoader.hFileContent, 0, nullptr);
				CloseHandle(EmuLoader.hFileContent);
			}
			return EmuLoader;
		}

		const auto pImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)EmuLoader.hFileContent + pImageDOSHeader->e_lfanew);
		if (pImageNTHeader == nullptr)
		{
			if (EmuLoader.hFileContent != nullptr)
			{
				HeapFree(EmuLoader.hFileContent, 0, nullptr);
				CloseHandle(EmuLoader.hFileContent);
			}
			return EmuLoader;
		}

		if (pImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			EmuLoader = ParseImageOfDll64(pImageDOSHeader, DllName, lpPathToDllWithName, uc, EmuLoader, NameOfExe);
		}
		else if (pImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			EmuLoader = ParseImageOfDll32(pImageDOSHeader, DllName, lpPathToDllWithName, uc, EmuLoader);
		}

		if (EmuLoader.hFileContent != nullptr)
		{
			HeapFree(EmuLoader.hFileContent, 0, nullptr);
		}

		return EmuLoader;
	}
} // namespace DllLoaderEmu