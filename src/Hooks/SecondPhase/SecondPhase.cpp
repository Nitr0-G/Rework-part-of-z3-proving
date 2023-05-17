#include "Phases/FirstPhase.hpp"
#include "z3/z3states.hpp"
#include "z3/z3ASMx64Instructions.hpp"

#include <Zydis/Zydis.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <z3++.h>

#include <immintrin.h>
#include <intrin.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <unordered_set>

namespace SecondPhase {
    x8664_ctx base; 

    z3::context z3c;

    namespace Eleminator
    {
        static inline void InstructionSender(
            uc_engine* uc,
            std::vector<ZydisDisassembledInstruction>& DeadCode,
            x8664_ctx& state, 
            std::vector<ZydisDisassembledInstruction>::iterator skip)
        {
            for (auto iter = DeadCode.begin(); iter != DeadCode.end(); ++iter)
            {
                if (iter != skip)
                {
                    AsmX64InstrsTranslate::InstructionChooser(uc, z3c, *iter, state);
                }
            }
        }

        static inline bool can_eliminate_instruction(
            uc_engine* uc,
            ZydisDisassembledInstruction& instruction,
            std::vector<ZydisDisassembledInstruction>& DeadCode,
            std::vector<ZydisDisassembledInstruction>::iterator it,
            bool SecondPhaseInProcess)
        {
            base.create_initial_state(z3c, base);

            x8664_ctx orig = base;
            x8664_ctx opt = base;

            InstructionSender(uc, DeadCode, orig, DeadCode.end());

            InstructionSender(uc, DeadCode, opt, it);

            z3::solver s(z3c);
            
            s.add(!(*orig.rax == *opt.rax && *orig.rbx == *opt.rbx && *orig.rcx == *opt.rcx && *orig.rdx == *opt.rdx && *orig.rbp == *opt.rbp && *orig.rsp == *opt.rsp && *orig.rsi == *opt.rsi 
                && *orig.rdi == *opt.rdi 
                && *orig.r8 == *opt.r8 && *orig.r9 == *opt.r9 && *orig.r10 == *opt.r10 && *orig.r11 == *opt.r11 && *orig.r12 == *opt.r12 && *orig.r13 == *opt.r13 && *orig.r14 == *opt.r14 
                && *orig.r15 == *opt.r15 && *orig.xmm0 == *opt.xmm0 && *orig.xmm1 == *opt.xmm1 && *orig.xmm2 == *opt.xmm2 && *orig.xmm3 == *opt.xmm3 && *orig.xmm4 == *opt.xmm4
                && *orig.xmm5 == *opt.xmm5 && *orig.xmm6 == *opt.xmm6 && *orig.xmm7 == *opt.xmm7 && *orig.xmm8 == *opt.xmm8 && *orig.xmm9 == *opt.xmm9 && *orig.xmm10 == *opt.xmm10
                && *orig.xmm11 == *opt.xmm11 && *orig.xmm12 == *opt.xmm12 && *orig.xmm13 == *opt.xmm13 && *orig.xmm14 == *opt.xmm14 && *orig.xmm15 == *opt.xmm15 && *orig.zf == *opt.zf 
                && *orig.of == *opt.of && *orig.cf == *opt.cf && *orig.pf == *opt.pf && *orig.sf == *opt.sf && *orig.af == *opt.af && *orig.df == *opt.df));
         
            return (s.check() == z3::unsat);
        }
    }

    static inline void DeadCodeEleminatorInit(
        uc_engine* uc,
        std::vector<ZydisDisassembledInstruction>& DeadCode,
        std::vector<ZydisDisassembledInstruction>& NullInstructions,
        ZydisDisassembledInstruction NullInstr,
        bool SecondPhaseInProcess)
    {
        bool eliminated; size_t Indexer = 0;
        do
        {
            eliminated = false; 
            auto DeadCodeiter = DeadCode.begin();

            for (auto iter = NullInstructions.begin(); iter != NullInstructions.end(); ++iter)
            {
                if (iter->runtime_address != NullInstr.runtime_address)
                {
                    if (Eleminator::can_eliminate_instruction(uc, *(DeadCodeiter), DeadCode, DeadCodeiter, SecondPhaseInProcess) == true)
                    {
                        std::cout << "Removing: " << iter->text << std::endl;
                        NullInstructions[Indexer] = NullInstr;

                        DeadCode.erase(DeadCodeiter);
                        eliminated = true;
                        break;
                    }
                    ++DeadCodeiter;
                }
                ++Indexer;
            }
            Indexer = 0;
        } while (eliminated);

        return;
    }


    void DeadCodeEleminator(
        uc_engine* uc,
        ZydisDisassembledInstruction& instruction,
        std::vector<ZydisDisassembledInstruction>& DeadCode,
        bool SecondPhaseInProcess)
    {
        static std::unordered_set<ZydisMnemonic> JccMnemonics{
             ZYDIS_MNEMONIC_JNBE, ZYDIS_MNEMONIC_JNB, ZYDIS_MNEMONIC_JB,
             ZYDIS_MNEMONIC_JBE, ZYDIS_MNEMONIC_JZ, ZYDIS_MNEMONIC_JNLE,
             ZYDIS_MNEMONIC_JNL, ZYDIS_MNEMONIC_JL, ZYDIS_MNEMONIC_JLE,
             ZYDIS_MNEMONIC_JNZ, ZYDIS_MNEMONIC_JNO, ZYDIS_MNEMONIC_JNP,
             ZYDIS_MNEMONIC_JNS, ZYDIS_MNEMONIC_JO, ZYDIS_MNEMONIC_JP,
             ZYDIS_MNEMONIC_JS };

        ZydisDisassembledInstruction NullInstr{};
        std::vector<ZydisDisassembledInstruction> SourceInstrs(DeadCode.size());
        std::vector<ZydisDisassembledInstruction> NullInstructions(DeadCode.size());

        std::copy(DeadCode.begin(), DeadCode.end(), SourceInstrs.begin());
        std::copy(DeadCode.begin(), DeadCode.end(), NullInstructions.begin());

        DeadCodeEleminatorInit(uc, DeadCode, NullInstructions, NullInstr, SecondPhaseInProcess);

        for (size_t Indexer = 0; Indexer <= SourceInstrs.size() - 1; ++Indexer)
        {
            if (JccMnemonics.count(SourceInstrs[Indexer].info.mnemonic) != 0)
            {
                NullInstructions[Indexer] = SourceInstrs[Indexer];

                for (size_t FromJcc = Indexer; FromJcc != 0;)
                {
                    --FromJcc;
                    for (size_t OpNum = 0; OpNum <= SourceInstrs[Indexer].info.operand_count; ++OpNum)
                    {
                        if (SourceInstrs[FromJcc].operands[OpNum].reg.value == ZYDIS_REGISTER_RFLAGS)
                        {
                            NullInstructions[FromJcc] = SourceInstrs[FromJcc];
                            break;
                        }
                    }
                    break;
                }
            }
        }
       
        return;
    }
}