#include "Emu.hpp"

#include <immintrin.h>
#include <intrin.h>
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <cstdio>
#include <strsafe.h>
#include <Psapi.h>
#include <string>
#include <queue>

int main(int argc, std::string argv) 
{
	Emu::UcStartUp(argv);

	return 0;
}