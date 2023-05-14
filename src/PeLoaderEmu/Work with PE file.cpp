#include "PeLoaderEmu.hpp"

#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <immintrin.h>
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <cstdio>
#include <strsafe.h>
#include <Psapi.h>
#include <string>
#include <intrin.h>

std::vector<std::string> DllsNames;
std::vector<std::string> SectionNames;

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

namespace PeLoaderEmu 
{
	/**
	 * Function to retrieve the PE file content.
	 * \param lpFilePath : path of the PE file.
	 * \return : address of the content in the explorer memory.
	 */
	static HANDLE GetFileContent(
		const std::string& lpFilePathWithName)
	{
		const HANDLE hFile = CreateFileA(lpFilePathWithName.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("[-] An error occured when trying to open the PE file !");
			CloseHandle(hFile);
			return nullptr;
		}

		const DWORD dFileSize = GetFileSize(hFile, nullptr);
		if (dFileSize == INVALID_FILE_SIZE)
		{
			printf("[-] An error occured when trying to get the PE file size !");
			CloseHandle(hFile);
			return nullptr;
		}

		const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
		if (hFileContent == INVALID_HANDLE_VALUE)
		{
			printf("[-] An error occured when trying to allocate memory for the PE file content !");
			CloseHandle(hFile);
			CloseHandle(hFileContent);
			return nullptr;
		}

		const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
		if (!bFileRead)
		{
			printf("[-] An error occured when trying to read the PE file content !");
			CloseHandle(hFile);
			if (hFileContent != nullptr) CloseHandle(hFileContent);

			return nullptr;
		}

		CloseHandle(hFile);
		return hFileContent;
	}

	/**
	 * Function to identify the PE file characteristics.
	 * \param dCharacteristics : characteristics in the file header section.
	 * \return : the description of the PE file characteristics.
	 */
	static const char* GetImageCharacteristics(
		const DWORD dCharacteristics)
	{
		if (dCharacteristics & IMAGE_FILE_DLL) return "(DLL)";

		if (dCharacteristics & IMAGE_FILE_SYSTEM) return "(DRIVER)";

		if (dCharacteristics & IMAGE_FILE_EXECUTABLE_IMAGE) return "(EXE)";

		return "(UNKNOWN)";
	}

	/**
	 * Function to identify the PE file subsystem.
	 * \param Subsystem : subsystem in the optional header.
	 * \return : the description of the PE file subsystem.
	 */
	static const char* GetSubsytem(
		const WORD Subsystem)
	{
		if (Subsystem == 1) return "(NATIVE / DRIVER)";

		if (Subsystem == 2) return "(GUI APP)";

		if (Subsystem == 3) return "(CONSOLE APP)";

		return "(UNKNOWN)";
	}

	/**
	 * Function to identify the DataDirectory.
	 * \param DirectoryNumber : index of the DataDirectory.
	 * \return : the description of the DataDirectory.
	 */
	static const char* GetDataDirectoryName(
		const int DirectoryNumber)
	{
		switch (DirectoryNumber)
		{
		case 0: return "Export Table";

		case 1: return "Import Table";

		case 2: return "Ressource Table";

		case 3: return "Exception Entry";

		case 4: return "Security Entry";

		case 5: return "Relocation Table";

		case 6: return "Debug Entry";

		case 7: return "Copyright Entry";

		case 8: return "Global PTR Entry";

		case 9: return "TLS Entry";

		case 10: return "Configuration Entry";

		case 11: return "Bound Import Entry";

		case 12: return "IAT";

		case 13: return "Delay Import Descriptor";

		case 14: return "COM Descriptor";

		default: return nullptr;
		}
	}

	/**
	 * Retrieve and display the DataDirectory informations.
	 * \param pImageDataDirectory : DataDirectory array of the optional header.
	 */
	static void GetDataDirectories(
		PIMAGE_DATA_DIRECTORY pImageDataDirectory)
	{
		for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i, ++pImageDataDirectory)
		{
			if (pImageDataDirectory->VirtualAddress == 0) continue;
		}
	}

	/**
	 * Retrieve and display the protection of the section.
	 * \param dCharacteristics : characteristics of the section.
	 * \return : the description of the protection.
	 */
	static const char* GetSectionProtection(
		DWORD dCharacteristics)
	{
		char lpSectionProtection[1024] = {};
		StringCchCatA(lpSectionProtection, 1024, "(");
		bool bExecute = false, bRead = false;

		if (dCharacteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			bExecute = true;
			StringCchCatA(lpSectionProtection, 1024, "EXECUTE");
		}

		if (dCharacteristics & IMAGE_SCN_MEM_READ)
		{
			bRead = true;
			if (bExecute) StringCchCatA(lpSectionProtection, 1024, " | ");
			StringCchCatA(lpSectionProtection, 1024, "READ");
		}

		if (dCharacteristics & IMAGE_SCN_MEM_WRITE)
		{
			if (bExecute || bRead) StringCchCatA(lpSectionProtection, 1024, " | ");
			StringCchCatA(lpSectionProtection, 1024, "WRITE");
		}

		StringCchCatA(lpSectionProtection, 1024, ")");
		return lpSectionProtection;
	}

	/**
	 * Function to Copy different buffers.
	 * \param dest : Destination buffer.
	 * \param src : Source buffer.
	 * \param size : Size for copy information.
	 * \return : none.
	 */
	void AVXMemcpy(
		void* dest, 
		const void* src, 
		size_t size)
	{
		const char* s = static_cast<const char*>(src);
		char* d = static_cast<char*>(dest);

		// Check for null pointers
		if (s == nullptr || d == nullptr)
		{
			return;
		}

		// Handle overlapping memory blocks
		if (s < d && s + size > d)
		{
			memmove(d, s, size);
		}
		else if (d < s && d + size > s)
		{
			memmove(d, s, size);
		}
		else
		{
			// Handle unaligned memory blocks
			if (reinterpret_cast<uintptr_t>(s) % 32 == 0 && reinterpret_cast<uintptr_t>(d) % 32 == 0 && size >= 32)
			{
				// Use AVX2 instructions to copy memory
				const size_t avx2_size = size / (32 * 16);
				const size_t remainder_size = size % (32 * 16);
				const __m256i* src_avx2 = reinterpret_cast<const __m256i*>(s);
				__m256i* dest_avx2 = reinterpret_cast<__m256i*>(d);
				for (size_t i = 0; i < avx2_size; ++i)
				{
					register __m256i ymm0 = _mm256_load_si256(src_avx2++);
					register __m256i ymm1 = _mm256_load_si256(src_avx2++);
					register __m256i ymm2 = _mm256_load_si256(src_avx2++);
					register __m256i ymm3 = _mm256_load_si256(src_avx2++);
					register __m256i ymm4 = _mm256_load_si256(src_avx2++);
					register __m256i ymm5 = _mm256_load_si256(src_avx2++);
					register __m256i ymm6 = _mm256_load_si256(src_avx2++);
					register __m256i ymm7 = _mm256_load_si256(src_avx2++);
					register __m256i ymm8 = _mm256_load_si256(src_avx2++);
					register __m256i ymm9 = _mm256_load_si256(src_avx2++);
					register __m256i ymm10 = _mm256_load_si256(src_avx2++);
					register __m256i ymm11 = _mm256_load_si256(src_avx2++);
					register __m256i ymm12 = _mm256_load_si256(src_avx2++);
					register __m256i ymm13 = _mm256_load_si256(src_avx2++);
					register __m256i ymm14 = _mm256_load_si256(src_avx2++);
					register __m256i ymm15 = _mm256_load_si256(src_avx2++);
					_mm256_store_si256(dest_avx2++, ymm0);
					_mm256_store_si256(dest_avx2++, ymm1);
					_mm256_store_si256(dest_avx2++, ymm2);
					_mm256_store_si256(dest_avx2++, ymm3);
					_mm256_store_si256(dest_avx2++, ymm4);
					_mm256_store_si256(dest_avx2++, ymm5);
					_mm256_store_si256(dest_avx2++, ymm6);
					_mm256_store_si256(dest_avx2++, ymm7);
					_mm256_store_si256(dest_avx2++, ymm8);
					_mm256_store_si256(dest_avx2++, ymm9);
					_mm256_store_si256(dest_avx2++, ymm10);
					_mm256_store_si256(dest_avx2++, ymm11);
					_mm256_store_si256(dest_avx2++, ymm12);
					_mm256_store_si256(dest_avx2++, ymm13);
					_mm256_store_si256(dest_avx2++, ymm14);
					_mm256_store_si256(dest_avx2++, ymm15);
				}
				memcpy(dest_avx2, src_avx2, remainder_size);
			}
			else
			{
				// Use standard memcpy for unaligned memory blocks
				memcpy(dest, src, size);
			}
		}
	}

	void SSEMemory(
		void* dest, 
		const void* src, 
		size_t size) 
	{
		const char* s = static_cast<const char*>(src);
		char* d = static_cast<char*>(dest);

		// Check for null pointers
		if (s == nullptr || d == nullptr)
		{
			return;
		}

		// Handle overlapping memory blocks
		if (s < d && s + size > d)
		{
			memmove(d, s, size);
		}
		else if (d < s && d + size > s)
		{
			memmove(d, s, size);
		}
		else
		{
			// Handle unaligned memory blocks
			if (reinterpret_cast<uintptr_t>(s) % 16 == 0 && reinterpret_cast<uintptr_t>(d) % 16 == 0 && size >= 16)
			{
				// Use SSE instructions to copy memory
				const size_t sse_size = size / (16 * 16);
				const size_t remainder_size = size % (16 * 16);
				const __m128i* src_sse = reinterpret_cast<const __m128i*>(s);
				__m128i* dest_sse = reinterpret_cast<__m128i*>(d);
				for (size_t i = 0; i < sse_size; ++i)
				{
					__m128i xmm0 = _mm_load_si128(src_sse++);
					__m128i xmm1 = _mm_load_si128(src_sse++);
					__m128i xmm2 = _mm_load_si128(src_sse++);
					__m128i xmm3 = _mm_load_si128(src_sse++);
					__m128i xmm4 = _mm_load_si128(src_sse++);
					__m128i xmm5 = _mm_load_si128(src_sse++);
					__m128i xmm6 = _mm_load_si128(src_sse++);
					__m128i xmm7 = _mm_load_si128(src_sse++);
					__m128i xmm8 = _mm_load_si128(src_sse++);
					__m128i xmm9 = _mm_load_si128(src_sse++);
					__m128i xmm10 = _mm_load_si128(src_sse++);
					__m128i xmm11 = _mm_load_si128(src_sse++);
					__m128i xmm12 = _mm_load_si128(src_sse++);
					__m128i xmm13 = _mm_load_si128(src_sse++);
					__m128i xmm14 = _mm_load_si128(src_sse++);
					__m128i xmm15 = _mm_load_si128(src_sse++);
					_mm_store_si128(dest_sse++, xmm0);
					_mm_store_si128(dest_sse++, xmm1);
					_mm_store_si128(dest_sse++, xmm2);
					_mm_store_si128(dest_sse++, xmm3);
					_mm_store_si128(dest_sse++, xmm4);
					_mm_store_si128(dest_sse++, xmm5);
					_mm_store_si128(dest_sse++, xmm6);
					_mm_store_si128(dest_sse++, xmm7);
					_mm_store_si128(dest_sse++, xmm8);
					_mm_store_si128(dest_sse++, xmm9);
					_mm_store_si128(dest_sse++, xmm10);
					_mm_store_si128(dest_sse++, xmm11);
					_mm_store_si128(dest_sse++, xmm12);
					_mm_store_si128(dest_sse++, xmm13);
					_mm_store_si128(dest_sse++, xmm14);
					_mm_store_si128(dest_sse++, xmm15);
				}
				memcpy(dest_sse, src_sse, remainder_size);
			}
			else
			{
				// Use standard memcpy for unaligned memory blocks
				memcpy(dest, src, size);
			}
		}
	}

	/**
	 * Function to Allocation sections from the PE file and get the section wich contains imports.
	 * \param pImageDOSHeader : DOS header of the PE file.
	 * \param pImageSectionHeader : section header of the PE file.
	 * \param pImageNTHeader64 : section header of the PE file.
	 * \param NumberOfSections : number of section in the PE file.
	 * \param uc_engine* : Handle from uc engine.
	 * \param HeaderAddress : Current address of header.
	 * \param uc_err : Errors handler in unicorn.
	 * \param Deques : My Struct with different containers and other stuff.
	 * \param FileMarkers : Markers for sections like system or user section.
	 * \return : LoaderEmu.
	 */
	static LoaderEmu HeaderAllocation64(
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_SECTION_HEADER pImageSectionHeader,
		const PIMAGE_NT_HEADERS64 pImageNTHeader64,
		const int NumberOfSections,
		uc_engine* uc,
		const uint64_t HeaderAddress,
		uc_err err,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe)
	{
		EmuLoader.Counter++;
		EmuLoader.svAOfSections.push_back(HeaderAddress);

		uint64_t sectionSize = (pImageNTHeader64->OptionalHeader.SizeOfHeaders + pImageNTHeader64->OptionalHeader.SectionAlignment - 1) & ~(pImageNTHeader64->OptionalHeader.SectionAlignment - 1);

		EmuLoader.svSizes.push_back(sectionSize);

		LPVOID sectionBaseAddress = VirtualAlloc(NULL, sectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		EmuLoader.svBAOfSections.push_back(sectionBaseAddress);

		 int cpuInfo[4];
		__cpuid(cpuInfo, 0);
		 if (cpuInfo[0] >= 7)
		 {
			 __cpuidex(cpuInfo, 7, 0);
			 if (cpuInfo[1] & (1 << 5))
			 {
				 AVXMemcpy(sectionBaseAddress, reinterpret_cast<LPVOID>(pImageDOSHeader), sectionSize);
			 }
			 else 
			 {
				 SSEMemory(sectionBaseAddress, reinterpret_cast<LPVOID>(pImageDOSHeader), sectionSize);
			 }
		 }

		err = uc_mem_map_ptr(uc, HeaderAddress, sectionSize, UC_PROT_ALL, sectionBaseAddress);
		if (err != UC_ERR_OK)
		{
			printf("Failed on uc_mem_map_ptr()(HeaderAllocation) with error returned: %d\n", err);
			VirtualFree(sectionBaseAddress, 0, MEM_RELEASE);
			return EmuLoader;
		}

		EmuLoader.svSizes.push_back(pImageNTHeader64->OptionalHeader.SizeOfHeaders);

		return EmuLoader;
	}

	static LoaderEmu HeaderAllocation32(
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_SECTION_HEADER pImageSectionHeader,
		const PIMAGE_NT_HEADERS32 pImageNTHeader32,
		const int NumberOfSections,
		uc_engine* uc,
		const uint64_t HeaderAddress,
		uc_err err,
		LoaderEmu& EmuLoader)
	{
		EmuLoader.Counter++;
		EmuLoader.svAOfSections.push_back(HeaderAddress);

		uint32_t sectionSize =
			(pImageNTHeader32->OptionalHeader.SizeOfHeaders + pImageNTHeader32->OptionalHeader.SectionAlignment - 1)
			& ~(pImageNTHeader32->OptionalHeader.SectionAlignment - 1);

		EmuLoader.svSizes.push_back(sectionSize);

		LPVOID sectionBaseAddress = VirtualAlloc(NULL, sectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		EmuLoader.svBAOfSections.push_back(sectionBaseAddress);

		 int cpuInfo[4];
		__cpuid(cpuInfo, 0);
		if (cpuInfo[0] >= 7)
		{
			__cpuidex(cpuInfo, 7, 0);
			if (cpuInfo[1] & (1 << 5))
			{
				AVXMemcpy(sectionBaseAddress, reinterpret_cast<LPVOID>(pImageDOSHeader), sectionSize);
			}
			else 
			{
				SSEMemory(sectionBaseAddress, reinterpret_cast<LPVOID>(pImageDOSHeader), sectionSize);
			}
		}

		err = uc_mem_map_ptr(uc, HeaderAddress, sectionSize, UC_PROT_ALL, sectionBaseAddress);
		if (err != UC_ERR_OK)
		{
			printf("Failed on uc_mem_map_ptr()(HeaderAllocation) with error returned: %d\n", err);
			VirtualFree(sectionBaseAddress, 0, MEM_RELEASE);
			return EmuLoader;
		}

		EmuLoader.svSizes.push_back(pImageNTHeader32->OptionalHeader.SizeOfHeaders);

		return EmuLoader;
	}

	/**
	 * Function to Allocation sections from the PE file and get the section wich contains imports.
	 * \param pImageDOSHeader : DOS header of the PE file.
	 * \param pImageSectionHeader : section header of the PE file.
	 * \param pImageNTHeader64 : section header of the PE file.
	 * \param NumberOfSections : number of section in the PE file.
	 * \param uc_engine* : Handle from uc engine.
	 * \param uc_err : Errors handler in unicorn.
	 * \param Deques : My Struct with different containers and other stuff.
	 * \param FileMarkers : Markers for sections like system or user section.
	 * \return : LoaderEmu.
	 */
	LoaderEmu SectionAllocation64(
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_SECTION_HEADER pImageSectionHeader,
		const PIMAGE_NT_HEADERS64 pImageNTHeader64,
		const int NumberOfSections,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe)
	{
		uint64_t HeaderAddress = (pImageNTHeader64->OptionalHeader.ImageBase);
		auto it{std::find(EmuLoader.svAOfSections.begin(), EmuLoader.svAOfSections.end(), HeaderAddress)};
		if (it == EmuLoader.svAOfSections.end())
		{
			uc_err err{};

			HeaderAllocation64(pImageDOSHeader,pImageSectionHeader,pImageNTHeader64,NumberOfSections,uc,HeaderAddress,err,EmuLoader,NameOfExe);
			EmuLoader.SizeOfStack += pImageNTHeader64->OptionalHeader.SizeOfStackReserve;

			for (int i = 0; i < NumberOfSections; ++i)
			{
				const PIMAGE_SECTION_HEADER pCurrentSectionHeader =
					(PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

				uint64_t sectionAddress =
					(pImageNTHeader64->OptionalHeader.ImageBase + pCurrentSectionHeader->VirtualAddress);

				auto it{std::find(EmuLoader.svAOfSections.begin(), EmuLoader.svAOfSections.end(), sectionAddress)};
				if (it == EmuLoader.svAOfSections.end())
				{
					EmuLoader.Counter++;
					EmuLoader.svAOfSections.push_back(sectionAddress);

					uint64_t sectionSize = (pCurrentSectionHeader->SizeOfRawData + pImageNTHeader64->OptionalHeader.SectionAlignment - 1) & ~(pImageNTHeader64->OptionalHeader.SectionAlignment - 1);

					EmuLoader.svSizes.push_back(sectionSize);

					LPVOID sectionBaseAddress = VirtualAlloc(nullptr, sectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

					EmuLoader.svBAOfSections.push_back(sectionBaseAddress);

					if (sectionBaseAddress == nullptr)
					{
						printf("Failed to allocate memory for section %s\n", pCurrentSectionHeader->Name);
						return EmuLoader;
					}

					int cpuInfo[4];
					__cpuid(cpuInfo, 0);
					if (cpuInfo[0] >= 7)
					{
						__cpuidex(cpuInfo, 7, 0);
						if (cpuInfo[1] & (1 << 5))
						{
							AVXMemcpy(sectionBaseAddress,LPVOID((uint64_t)pImageDOSHeader + pCurrentSectionHeader->PointerToRawData), pCurrentSectionHeader->SizeOfRawData);
						}
						else 
						{
							SSEMemory(sectionBaseAddress,LPVOID((uint64_t)pImageDOSHeader + pCurrentSectionHeader->PointerToRawData), pCurrentSectionHeader->SizeOfRawData);
						}
					}	

					err = uc_mem_map_ptr(uc, sectionAddress, sectionSize, UC_PROT_ALL, sectionBaseAddress);
					if (err != UC_ERR_OK)
					{
						printf("Failed on uc_mem_map_ptr()(SectionAllocation) with error returned: %d\n", err);
						VirtualFree(sectionBaseAddress, 0, MEM_RELEASE);
						return EmuLoader;
					}

					printf("\tSection from address %p and with name %s copied to address %p\n", (void*)sectionAddress, pCurrentSectionHeader->Name, sectionBaseAddress);
				}
				else
				{
					printf("Memory region is already mapped or reserved\n");
					return EmuLoader;
				}
			}
			return EmuLoader;
		}
		else
		{
			printf("Header of this file is already mapped or reserved\n");
			return EmuLoader;
		}
	}

	LoaderEmu SectionAllocation32(
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_SECTION_HEADER pImageSectionHeader,
		const PIMAGE_NT_HEADERS32 pImageNTHeader32,
		const int NumberOfSections,
		uc_engine* uc,
		LoaderEmu& EmuLoader)
	{
		uint32_t HeaderAddress = (pImageNTHeader32->OptionalHeader.ImageBase);
		auto it{std::find(EmuLoader.svAOfSections.begin(), EmuLoader.svAOfSections.end(), HeaderAddress)};
		if (it == EmuLoader.svAOfSections.end())
		{
			uc_err err{};

			HeaderAllocation32(pImageDOSHeader,pImageSectionHeader,pImageNTHeader32,NumberOfSections,uc,HeaderAddress,err,EmuLoader);
			for (int i = 0; i < NumberOfSections; ++i)
			{
				const PIMAGE_SECTION_HEADER pCurrentSectionHeader =
					(PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

				uint32_t sectionAddress =
					(pImageNTHeader32->OptionalHeader.ImageBase + pCurrentSectionHeader->VirtualAddress);
				auto it{std::find(EmuLoader.svAOfSections.begin(), EmuLoader.svAOfSections.end(), sectionAddress)};
				if (it == EmuLoader.svAOfSections.end())
				{
					EmuLoader.Counter++;
					EmuLoader.svAOfSections.push_back(sectionAddress);

					uint32_t sectionSize = (pCurrentSectionHeader->SizeOfRawData + pImageNTHeader32->OptionalHeader.SectionAlignment - 1) & ~(pImageNTHeader32->OptionalHeader.SectionAlignment - 1);

					EmuLoader.svSizes.push_back(sectionSize);

					LPVOID sectionBaseAddress = VirtualAlloc(nullptr, sectionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

					EmuLoader.svBAOfSections.push_back(sectionBaseAddress);

					if (sectionBaseAddress == nullptr)
					{
						printf("Failed to allocate memory for section %s\n", pCurrentSectionHeader->Name);
						return EmuLoader;
					}

					int cpuInfo[4];
					__cpuid(cpuInfo, 0);
					if (cpuInfo[0] >= 7)
					{
						__cpuidex(cpuInfo, 7, 0);
						if (cpuInfo[1] & (1 << 5))
						{
							AVXMemcpy(sectionBaseAddress,LPVOID((uint32_t)pImageDOSHeader + pCurrentSectionHeader->PointerToRawData),pCurrentSectionHeader->SizeOfRawData);
						}
						else 
						{
							SSEMemory(sectionBaseAddress,LPVOID((uint32_t)pImageDOSHeader + pCurrentSectionHeader->PointerToRawData),pCurrentSectionHeader->SizeOfRawData);
						}
					}	

					err = uc_mem_map_ptr(uc, sectionAddress, sectionSize, UC_PROT_ALL, sectionBaseAddress);
					if (err != UC_ERR_OK)
					{
						printf("Failed on uc_mem_map_ptr()(SectionAllocation) with error returned: %d\n", err);
						VirtualFree(sectionBaseAddress, 0, MEM_RELEASE);
						return EmuLoader;
					}

					printf("\tSection from address %p and with name %s copied to address %p\n",(void*)sectionAddress,pCurrentSectionHeader->Name,sectionBaseAddress);
				}
				else
				{
					printf("Memory region is already mapped or reserved\n");
					return EmuLoader;
				}
			}
			return EmuLoader;
		}
		else
		{
			printf("Header of this file is already mapped or reserved\n");
			return EmuLoader;
		}
	}

	/**
	 * Function to retrieve sections from the PE file and get the section wich contains imports.
	 * \param pImageSectionHeader : section header of the PE file.
	 * \param NumberOfSections : number of section in the PE file.
	 * \param dImportAddress : address of import found into DataDirectory 1.
	 * \return : section which contains imports.
	 */
	static PIMAGE_SECTION_HEADER GetSections32(
		const PIMAGE_SECTION_HEADER pImageSectionHeader, 
		const int NumberOfSections, 
		const DWORD32 dImportAddress)
	{
		PIMAGE_SECTION_HEADER pImageImportHeader = nullptr;

		for (int i = 0; i < NumberOfSections; ++i)
		{
			const auto pCurrentSectionHeader =
				(PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

			if (dImportAddress >= pCurrentSectionHeader->VirtualAddress
				&& dImportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
				pImageImportHeader = pCurrentSectionHeader;
		}

		return pImageImportHeader;
	}

	/**
	 * Function to retrieve sections from the PE file and get the section wich contains imports.
	 * \param pImageSectionHeader : section header of the PE file.
	 * \param NumberOfSections : number of section in the PE file.
	 * \param dImportAddress : address of import found into DataDirectory 1.
	 * \return : section which contains imports.
	 */
	PIMAGE_SECTION_HEADER GetSections64(
		const PIMAGE_SECTION_HEADER pImageSectionHeader,
		const int NumberOfSections,
		const DWORD dImportAddress,
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_NT_HEADERS64 pImageNTHeader64,
		uc_engine* uc)
	{
		PIMAGE_SECTION_HEADER pImageImportHeader = nullptr;

		for (int i = 0; i < NumberOfSections; ++i)
		{
			const PIMAGE_SECTION_HEADER pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

			if (dImportAddress >= pCurrentSectionHeader->VirtualAddress
				&& dImportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
				pImageImportHeader = pCurrentSectionHeader;
		}

		return pImageImportHeader;
	}

	/**
	 * Retrieve and display dll and functions imported (for x86 PE file).
	 * \param pImageImportDescriptor : import descriptor of the PE file.
	 * \param dRawOffset : address of raw data of the import section.
	 * \param pImageImportSection : section wich contains imports.
	 */
	static LoaderEmu GetImports32(
		PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor,
		const DWORD64 dRawOffset,
		LoaderEmu& EmuLoader,
		const PIMAGE_SECTION_HEADER pImageImportSection,
		const std::string& lpFilePath, 
		uc_engine* uc, 
		std::string& NameOfExe)
	{
		while (pImageImportDescriptor->Name != 0)
		{
			char* temp = (char*)(dRawOffset + (pImageImportDescriptor->Name - pImageImportSection->VirtualAddress));
			printf("\n\tDLL NAME: %s\n", temp);
			std::string DllName(temp);
			const std::string& lpPathToDllWithName(lpFilePath + "\\" + DllName);

			EmuLoader = DllLoaderEmu::WorkWithDll(DllName, lpPathToDllWithName, uc, EmuLoader, NameOfExe);

			if (pImageImportDescriptor->OriginalFirstThunk == 0) continue;

			PIMAGE_THUNK_DATA32 pOriginalFirstThrunk =
				(PIMAGE_THUNK_DATA32)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress));

			while (pOriginalFirstThrunk->u1.AddressOfData != 0)
			{
				if (pOriginalFirstThrunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG32)
				{
					++pOriginalFirstThrunk;
					continue;
				}

				const PIMAGE_IMPORT_BY_NAME pImageImportByName =
					(PIMAGE_IMPORT_BY_NAME)pOriginalFirstThrunk->u1.AddressOfData;
				if (pImageImportByName == nullptr) continue;

				temp = dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress);

				if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThrunk->u1.Ordinal))
				{
					FARPROC pfnProc = GetProcAddress((HMODULE)EmuLoader.hFileContent, (LPCSTR)pOriginalFirstThrunk->u1.Ordinal);
					if (pfnProc == NULL)
					{
						printf("\t\tpfnProc is null\n");
						return EmuLoader;
					}
					pOriginalFirstThrunk->u1.Function = (DWORD32)pfnProc;
				}
				else 
				{
					FARPROC pfnProc = GetProcAddress((HMODULE)EmuLoader.hFileContent, (LPCSTR(temp)));
					if (pfnProc == NULL)
					{
						printf("\t\tpfnProc is null\n");
						return EmuLoader;
					}
					pOriginalFirstThrunk->u1.Function = (DWORD32)pfnProc;
				}
				++pOriginalFirstThrunk;
			}
			++pImageImportDescriptor;
		}
		return EmuLoader;
	}

	/**
	 * Retrieve and display dll and functions imported (for x64 PE file).
	 * \param pImageImportDescriptor : import descriptor of the PE file.
	 * \param dRawOffset : address of raw data of the import section.
	 * \param pImageImportSection : section wich contains imports.
	 */
	static LoaderEmu GetImports64(
		PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor,
		uint64_t dRawOffset,
		const PIMAGE_SECTION_HEADER pImageImportSection,
		const PIMAGE_DOS_HEADER pImageDOSHeader,
		const PIMAGE_NT_HEADERS64 pImageNTHeader64,
		const std::string& lpFilePath,
		const std::string& lpFilePathWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe)
	{
		while (pImageImportDescriptor->Name != 0)
		{
			char* temp = (char*)(dRawOffset + (pImageImportDescriptor->Name - pImageImportSection->VirtualAddress));
			printf("\n\tDLL NAME: %s\n", temp);
			std::string DllName(temp);
			const std::string& lpPathToDllWithName(lpFilePath + "\\" + DllName);

			EmuLoader = DllLoaderEmu::WorkWithDll(DllName, lpPathToDllWithName, uc, EmuLoader, NameOfExe);

			if (pImageImportDescriptor->OriginalFirstThunk == 0) continue;

			PIMAGE_THUNK_DATA64 pOriginalFirstThrunk =
				(PIMAGE_THUNK_DATA64)(dRawOffset + (pImageImportDescriptor->OriginalFirstThunk - pImageImportSection->VirtualAddress));

			while (pOriginalFirstThrunk->u1.AddressOfData != 0)
			{
				if (pOriginalFirstThrunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG64)
				{
					++pOriginalFirstThrunk;
					continue;
				}

				const PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME)pOriginalFirstThrunk->u1.AddressOfData;
				if (pImageImportByName == nullptr) continue;

				temp = dRawOffset + (pImageImportByName->Name - pImageImportSection->VirtualAddress);

				if (IMAGE_SNAP_BY_ORDINAL(pOriginalFirstThrunk->u1.Ordinal))
				{
					FARPROC pfnProc = GetProcAddress((HMODULE)EmuLoader.hFileContent, (LPCSTR)pOriginalFirstThrunk->u1.Ordinal);
					if (pfnProc == NULL)
					{
						printf("\t\tpfnProc is null\n");
						return EmuLoader;
					}
					pOriginalFirstThrunk->u1.Function = (ULONGLONG)pfnProc;
				}
				else
				{
					FARPROC pfnProc = GetProcAddress((HMODULE)EmuLoader.hFileContent, (LPCSTR(temp)));
					if (pfnProc == NULL)
					{
						printf("\t\tpfnProc is null\n");
						return EmuLoader;
					}
					pOriginalFirstThrunk->u1.Function = (ULONGLONG)pfnProc;
				}
				++pOriginalFirstThrunk;
			}
			++pImageImportDescriptor;
		}
		return EmuLoader;
	}

	/**
	 * Retrieve the section wich contains exports.
	 * \param pImageSectionHeader : section header of the Pe file.
	 * \param NumberOfSections : number of sections.
	 * \param dExportAddress : export address get from the DataDirectory 0.
	 * \return : the section wich conatins exports.
	 */
	static PIMAGE_SECTION_HEADER GetExportSection(
		const PIMAGE_SECTION_HEADER pImageSectionHeader, 
		const int NumberOfSections, 
		const DWORD64 dExportAddress)
	{
		PIMAGE_SECTION_HEADER pImageImportHeader = nullptr;

		for (int i = 0; i < NumberOfSections; ++i)
		{
			const PIMAGE_SECTION_HEADER pCurrentSectionHeader =
				(PIMAGE_SECTION_HEADER)((DWORD64)pImageSectionHeader + i * sizeof(IMAGE_SECTION_HEADER));

			if (dExportAddress >= pCurrentSectionHeader->VirtualAddress
				&& dExportAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
				pImageImportHeader = pCurrentSectionHeader;
		}

		return pImageImportHeader;
	}

	/**
	 * Retrieve and display exported functions.
	 * \param pImageExportDirectory : export directory wich contains every informations on exported functions.
	 * \param dRawOffset : address of raw data of the section wich contains exports.
	 * \param pImageExportSection : section wich contains exports.
	 */
	static void GetExports(
		const PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
		const DWORD64 dRawOffset,
		const PIMAGE_SECTION_HEADER pImageExportSection)
	{
		printf("\n[+] EXPORTED FUNCTIONS\n\n");

		const DWORD64 dNumberOfNames = (DWORD64)pImageExportDirectory->NumberOfNames;
		const int* pArrayOfFunctionsNames =
			((int*)((dRawOffset + (pImageExportDirectory->AddressOfNames - pImageExportSection->VirtualAddress))));

		for (int i = 0; i < dNumberOfNames; ++i)
			printf("\t%s\n", (char*)(dRawOffset + (pArrayOfFunctionsNames[i] - pImageExportSection->VirtualAddress)));
	}

	/**
	 * Function wich parse x86 PE file.
	 * \param pImageDOSHeader : pointer of the DOS header of the PE file.
	 * \return : 0 if the parsing is succeful else -1.
	 */
	static LoaderEmu ParseImage32(
		const PIMAGE_DOS_HEADER pImageDOSHeader, 
		uc_engine* uc,
		LoaderEmu& EmuLoader, 
		const std::string& lpFilePath, 
		std::string& NameOfExe)
	{
		const PIMAGE_NT_HEADERS32 pImageNTHeader32 =
			(PIMAGE_NT_HEADERS32)((DWORD_PTR)pImageDOSHeader + pImageDOSHeader->e_lfanew);
		if (pImageNTHeader32 == nullptr) return EmuLoader;

		const IMAGE_FILE_HEADER ImageFileHeader = pImageNTHeader32->FileHeader;
		const IMAGE_OPTIONAL_HEADER32 ImageOptionalHeader32 = pImageNTHeader32->OptionalHeader;

		const PIMAGE_SECTION_HEADER pImageSectionHeader =
			(PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + ImageFileHeader.SizeOfOptionalHeader);
		if (pImageSectionHeader == nullptr) return EmuLoader;

		EmuLoader.EP = pImageNTHeader32->OptionalHeader.AddressOfEntryPoint + pImageNTHeader32->OptionalHeader.ImageBase;

		GetDataDirectories((PIMAGE_DATA_DIRECTORY)ImageOptionalHeader32.DataDirectory);

		const PIMAGE_SECTION_HEADER pImageImportSection = GetSections32(
			pImageSectionHeader, ImageFileHeader.NumberOfSections, ImageOptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		if (pImageImportSection == nullptr)
		{
			printf("\n[-] An error when trying to retrieve PE imports !\n");
			return EmuLoader;
		}

		DWORD64 dRawOffset = (DWORD64)pImageDOSHeader + pImageImportSection->PointerToRawData;
		const PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(DWORD64(
			dRawOffset + (ImageOptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - pImageImportSection->VirtualAddress)));

		if (pImageImportDescriptor == nullptr)
		{
			printf("\n[-] An error occured when trying to retrieve PE imports descriptor !\n");
			return EmuLoader;
		}

		GetImports32(pImageImportDescriptor, dRawOffset, EmuLoader, pImageImportSection, lpFilePath, uc, NameOfExe);

		const PIMAGE_SECTION_HEADER pImageExportSection = GetExportSection(
			pImageSectionHeader, ImageFileHeader.NumberOfSections, ImageOptionalHeader32.DataDirectory[0].VirtualAddress);
		if (pImageExportSection != nullptr)
		{
			dRawOffset = (DWORD64)pImageDOSHeader + pImageExportSection->PointerToRawData;
			const PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dRawOffset + (ImageOptionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - pImageExportSection->VirtualAddress));
			GetExports(pImageExportDirectory, dRawOffset, pImageExportSection);
		}

		//EmuLoader = SectionAllocation32(
		//	pImageDOSHeader,
		//	pImageSectionHeader,
		//	pImageNTHeader32,
		//	ImageFileHeader.NumberOfSections,
		//	uc,
		//	EmuLoader);

		return EmuLoader;
	}

	/**
	 * Function wich parse x64 PE file.
	 * \param pImageDOSHeader : pointer of the DOS header of the PE file.
	 * \return : 0 if the parsing is succeful else -1.
	 */
	static LoaderEmu ParseImage64(
		PIMAGE_DOS_HEADER pImageDOSHeader,
		const std::string& lpFilePath,
		const std::string& lpFilePathWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe)
	{
		const auto pImageNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)pImageDOSHeader + pImageDOSHeader->e_lfanew);
		if (pImageNTHeader64 == nullptr)
		{
			return EmuLoader;
		}

		const IMAGE_FILE_HEADER ImageFileHeader = pImageNTHeader64->FileHeader;
		const IMAGE_OPTIONAL_HEADER64 ImageOptionalHeader64 = pImageNTHeader64->OptionalHeader;

		const auto pImageSectionHeader =
			(PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + ImageFileHeader.SizeOfOptionalHeader);
		if (pImageSectionHeader == nullptr)
		{
			return EmuLoader;
		}

		EmuLoader.EP = pImageNTHeader64->OptionalHeader.AddressOfEntryPoint + pImageNTHeader64->OptionalHeader.ImageBase;

		GetDataDirectories((PIMAGE_DATA_DIRECTORY)ImageOptionalHeader64.DataDirectory);

		const PIMAGE_SECTION_HEADER pImageImportSection = GetSections64(
			pImageSectionHeader,
			ImageFileHeader.NumberOfSections,
			ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress,
			pImageDOSHeader,
			pImageNTHeader64,
			uc);

		if (pImageImportSection == nullptr)
		{
			printf("\n[-] An error when trying to retrieve PE imports !\n");
			return EmuLoader;
		}

		uint64_t dRawOffset = (uint64_t)pImageDOSHeader + pImageImportSection->PointerToRawData;

		const PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = PIMAGE_IMPORT_DESCRIPTOR(
			(uint64_t(dRawOffset + (ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - pImageImportSection->VirtualAddress))));

		if (pImageImportDescriptor == NULL)
		{
			printf("\n[-] An error occurred when trying to retrieve PE imports descriptor!\n");
			return EmuLoader;
		}

		EmuLoader = GetImports64(
			pImageImportDescriptor,
			dRawOffset,
			pImageImportSection,
			pImageDOSHeader,
			pImageNTHeader64,
			lpFilePath,
			lpFilePathWithName,
			uc,
			EmuLoader,
			NameOfExe);


		const PIMAGE_SECTION_HEADER pImageExportSection = GetExportSection(
			pImageSectionHeader, ImageFileHeader.NumberOfSections, ImageOptionalHeader64.DataDirectory[0].VirtualAddress);

		if (pImageExportSection != nullptr)
		{
			dRawOffset = (uint64_t)pImageDOSHeader + pImageExportSection->PointerToRawData;
			const auto pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uint64_t(dRawOffset + (ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress - pImageExportSection->VirtualAddress)));
			GetExports(pImageExportDirectory, dRawOffset, pImageExportSection);
		}

		EmuLoader = SectionAllocation64(
			pImageDOSHeader,
			pImageSectionHeader,
			pImageNTHeader64,
			ImageFileHeader.NumberOfSections,
			uc,
			EmuLoader,
			NameOfExe);

		return EmuLoader;
	}

	LoaderEmu WorkWithPe(
		const std::string& lpFilePath,
		const std::string& lpFilePathWithName,
		uc_engine* uc,
		LoaderEmu& EmuLoader,
		std::string& NameOfExe)
	{
		// Identify x86 and x64 PE files.
		if (EmuLoader.pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			EmuLoader = ParseImage32(EmuLoader.pImageDOSHeaderOfPe, uc, EmuLoader, lpFilePath, NameOfExe);
		}

		if (EmuLoader.pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			EmuLoader = ParseImage64(EmuLoader.pImageDOSHeaderOfPe, lpFilePath, lpFilePathWithName, uc, EmuLoader, NameOfExe);
		}

		if (EmuLoader.hPeFileContent != nullptr)
		{
			HeapFree(EmuLoader.hPeFileContent, 0, nullptr);
		}
		if (EmuLoader.hFileContent != nullptr)
		{
			HeapFree(EmuLoader.hFileContent, 0, nullptr);
		}

		return EmuLoader;
	}

	LoaderEmu PeInit(
		const std::string& lpFilePathWithName, 
		LoaderEmu& EmuLoader) 
	{
		EmuLoader.hPeFileContent = GetFileContent(lpFilePathWithName);
		if (EmuLoader.hPeFileContent == INVALID_HANDLE_VALUE)
		{
			if (EmuLoader.hPeFileContent != nullptr)
			{
				CloseHandle(EmuLoader.hPeFileContent);
				return EmuLoader;
			}
		}

		EmuLoader.pImageDOSHeaderOfPe = (PIMAGE_DOS_HEADER)EmuLoader.hPeFileContent;
		if (EmuLoader.pImageDOSHeaderOfPe == nullptr)
		{
			if (EmuLoader.hPeFileContent != nullptr)
			{
				HeapFree(EmuLoader.hPeFileContent, 0, nullptr);
				CloseHandle(EmuLoader.hPeFileContent);
				return EmuLoader;
			}
		}

		EmuLoader.pImageNTHeaderOfPe = (PIMAGE_NT_HEADERS)((DWORD_PTR)EmuLoader.hPeFileContent + EmuLoader.pImageDOSHeaderOfPe->e_lfanew);
		if (EmuLoader.pImageNTHeaderOfPe == nullptr)
		{
			if (EmuLoader.hPeFileContent != nullptr)
			{
				HeapFree(EmuLoader.hPeFileContent, 0, nullptr);
				CloseHandle(EmuLoader.hPeFileContent);
				return EmuLoader;
			}
		}

		if (EmuLoader.pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			EmuLoader.BitMode = UC_MODE_32;
		}
		else if (EmuLoader.pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			EmuLoader.BitMode = UC_MODE_64;
		}

		return EmuLoader;
	}
} // namespace PeLoaderEmu