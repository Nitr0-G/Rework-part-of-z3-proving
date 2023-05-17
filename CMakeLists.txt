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
    "src/Emu.cpp"
    "include/Emu.hpp"
    "src/Dynamic-retdec-decompiler.cpp"
    "src/PeLoaderEmu/Work with PE file.cpp"
    "src/PeLoaderEmu/Work with DLL.cpp"
    "include/PeLoaderEmu.hpp"
    "src/Hooks/HooksFromEmu.cpp"
    "include/HooksFromEmu.hpp"
    "src/Hooks/FirstPhase/FirstPhase.cpp"
    "include/Phases/FirstPhase.hpp"
    "src/Hooks/SecondPhase/SecondPhase.cpp"
    "include/Phases/SecondPhase.hpp"
    "include/z3/z3states.hpp"
    "include/z3/z3ASMx64Instructions.hpp"
    "src/z3/z3ASMx64Instructions.cpp")

# Have CMake link our project executable against Zydis.
target_link_directories(${PROJECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/CompiledDeps/z3-4.12.2-x64-win/bin")

target_link_libraries(${PROJECT_NAME} PRIVATE Zydis
     PRIVATE unicorn PRIVATE "libz3.lib")

target_include_directories(${PROJECT_NAME} PRIVATE Zydis PRIVATE unicorn
     PRIVATE "include/" PRIVATE "${CMAKE_SOURCE_DIR}/CompiledDeps/z3-4.12.2-x64-win/include/")

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)
