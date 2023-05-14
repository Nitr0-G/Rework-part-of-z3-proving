cmake_minimum_required(VERSION 3.15)
include(FetchContent)
project("DynamicRetDec")

FetchContent_Declare(
  Zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG        master
)
set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Zydis)

FetchContent_Declare(
  unicorn
  GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
  GIT_TAG        master
)
FetchContent_MakeAvailable(unicorn)

# Add our project executable
add_executable(${PROJECT_NAME}
    "src/dynamic-retdec-decompiler/Emu.cpp"
    "src/dynamic-retdec-decompiler/Emu.hpp"
    "src/dynamic-retdec-decompiler/Dynamic-retdec-decompiler.cpp"
    "src/dynamic-retdec-decompiler/PeLoaderEmu/Work with PE file.cpp"
    "src/dynamic-retdec-decompiler/PeLoaderEmu/Work with DLL.cpp"
    "src/dynamic-retdec-decompiler/PeLoaderEmu/PeLoaderEmu.hpp"
    "src/dynamic-retdec-decompiler/Hooks/HooksFromEmu.cpp"
    "src/dynamic-retdec-decompiler/Hooks/HooksFromEmu.hpp"
    "src/dynamic-retdec-decompiler/Hooks/FirstPhase/FirstPhase.cpp"
    "src/dynamic-retdec-decompiler/Hooks/FirstPhase/FirstPhase.hpp"
    "src/dynamic-retdec-decompiler/z3/z3states.hpp"
    "src/dynamic-retdec-decompiler/z3/z3ASMx64Instructions.hpp"
    "src/dynamic-retdec-decompiler/z3/z3ASMx64Instructions.cpp")

# Have CMake link our project executable against Zydis.
target_link_libraries(${PROJECT_NAME} PRIVATE Zydis 
     PRIVATE unicorn)

target_include_directories(${PROJECT_NAME} PRIVATE Zydis PRIVATE unicorn)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)