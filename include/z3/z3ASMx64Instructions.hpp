#pragma once

#include "z3/z3states.hpp"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

#include <z3++.h>

namespace AsmX64InstrsTranslate {
	void InstructionChooser(uc_engine* uc, z3::context& z3c, ZydisDisassembledInstruction ins, x8664_ctx& old_state);
}