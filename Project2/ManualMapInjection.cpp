#include "ManualMapInjection.h"
#include <cstdio>
#include <random>
#include <iostream>
#include <vector>
#include <mutex>

// Constants for error codes
#define INVALID_DATA_POINTER ((HINSTANCE)0x404040)
#define SEH_SUPPORT_FAILED ((HINSTANCE)0x505050)
constexpr DWORD SHELLCODE_SIZE = 0x1000;

// Structure to track injection information for cleanup
struct InjectionInfo {
    HANDLE hProcess;
    BYTE* baseAddress;
    DWORD imageSize;
    DWORD originalImageSize; // Store original PE size before expansion
    BYTE* allocationBase;    // Store the original allocation base
    std::string dllName;     // Store the DLL name for identification
};

// Global injection tracking
static std::vector<InjectionInfo> g_injections;
static std::mutex g_injectionMutex;

#define RELOC_FLAG(RelInfo) (((RelInfo) >> 12) == IMAGE_REL_BASED_DIR64)

// Helper function to free remote memory
static void FreeRemoteMemory(HANDLE hProc, LPVOID ptr) {
    if (ptr) VirtualFreeEx(hProc, ptr, 0, MEM_RELEASE);
}

// Generate a random base address for DLL injection (ASLR-style)
static BYTE* GenerateRandomBaseAddress(DWORD imageSize) {
    static std::random_device rd;
    static std::mt19937 gen(rd() ^ static_cast<unsigned int>(GetTickCount64()));
    
    // For 64-bit, use addresses in user space range
    // Avoid common ranges like 0x140000000 (typical exe base)
    std::uniform_int_distribution<ULONG_PTR> dist(0x10000000ULL, 0x7FF00000000ULL);
    
    ULONG_PTR baseAddr = dist(gen);
    
    // Align to allocation granularity (64KB)
    baseAddr &= ~0xFFFF;
    baseAddr += 0x10000;
    
    // Ensure we don't overflow when adding image size
    if (baseAddr > (SIZE_T(-1) - imageSize)) {
        baseAddr = 0x10000000;
    }
    
    return reinterpret_cast<BYTE*>(baseAddr);
}

namespace Inject {
    // Add injection to tracking list
    static void TrackInjection(HANDLE hProcess, BYTE* baseAddress, DWORD originalImageSize, const std::string& dllName) {
        std::lock_guard<std::mutex> lock(g_injectionMutex);
        
        // Query actual allocated information
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T actualSize = originalImageSize;
        BYTE* allocationBase = baseAddress;
        
        if (VirtualQueryEx(hProcess, baseAddress, &mbi, sizeof(mbi)) != 0) {
            actualSize = mbi.RegionSize;
            allocationBase = (BYTE*)mbi.AllocationBase;
        }
        
        InjectionInfo info;
        info.hProcess = hProcess;
        info.baseAddress = baseAddress;
        info.imageSize = static_cast<DWORD>(actualSize);
        info.originalImageSize = originalImageSize; // Store original PE size
        info.allocationBase = allocationBase;
        info.dllName = dllName;
        
        g_injections.push_back(info);
    }

    // Direct cleanup function - performs immediate cleanup of all injections
    void PerformCleanup() {
        std::lock_guard<std::mutex> lock(g_injectionMutex);
        
        for (auto it = g_injections.begin(); it != g_injections.end(); ++it) {
            // Query the memory region at the base address
            MEMORY_BASIC_INFORMATION mbi = {};
            SIZE_T queryResult = VirtualQueryEx(it->hProcess, it->baseAddress, &mbi, sizeof(mbi));
            
            if (queryResult == 0) {
                continue;
            }
            
            // First, wipe the memory content for stealth
            SIZE_T wipeSize = it->originalImageSize; // Use original PE size for wiping
            
            // Change memory protection to ensure we can write to it
            DWORD oldProtect = 0;
            if (VirtualProtectEx(it->hProcess, it->baseAddress, wipeSize, PAGE_READWRITE, &oldProtect)) {
                // Zero out the memory in chunks for better reliability
                const SIZE_T CHUNK_SIZE = 64 * 1024; // 64KB chunks
                
                for (SIZE_T offset = 0; offset < wipeSize; offset += CHUNK_SIZE) {
                    SIZE_T chunkSize = min(CHUNK_SIZE, wipeSize - offset);
                    BYTE* chunkAddr = it->baseAddress + offset;
                    
                    BYTE* zeroBuffer = new(std::nothrow) BYTE[chunkSize];
                    if (zeroBuffer) {
                        memset(zeroBuffer, 0, chunkSize);
                        
                        SIZE_T bytesWritten = 0;
                        WriteProcessMemory(it->hProcess, chunkAddr, zeroBuffer, chunkSize, &bytesWritten);
                        
                        delete[] zeroBuffer;
                    }
                }
            }
            
            // Now free the memory - use the allocation base for proper cleanup
            if (!VirtualFreeEx(it->hProcess, it->allocationBase, 0, MEM_RELEASE)) {
                // If freeing at allocation base fails, try freeing at the base address
                VirtualFreeEx(it->hProcess, it->baseAddress, 0, MEM_RELEASE);
            }
        }
        
        // Clear all tracked injections
        g_injections.clear();
    }

    // Get the number of tracked injections (for display purposes)
    size_t GetTrackedInjectionCount() {
        std::lock_guard<std::mutex> lock(g_injectionMutex);
        return g_injections.size();
    }

    // Cleanup function to stop tracking (used when you want to leave DLLs injected)
    void CleanupInjectionTracking() {
        std::lock_guard<std::mutex> lock(g_injectionMutex);
        g_injections.clear();
    }

    bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, bool SEHExceptionSupport, DWORD fdwReason, LPVOID lpReserved, const std::string& dllName) {
        // Validate PE signature
        if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D) {
            return false;
        }

        const auto pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
        const auto pOldOptHeader = &pOldNtHeader->OptionalHeader;
        const auto pOldFileHeader = &pOldNtHeader->FileHeader;

        BYTE* pTargetBase = nullptr;
        
        // Try to allocate at random addresses (up to 3 attempts)
        for (int attempts = 0; attempts < 3 && !pTargetBase; ++attempts) {
            BYTE* randomAddr = GenerateRandomBaseAddress(pOldOptHeader->SizeOfImage);
            pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, randomAddr, pOldOptHeader->SizeOfImage, 
                                                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        }
        
        // If random allocation failed, fall back to system choice
        if (!pTargetBase) {
            pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, 
                                                               MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        }
        
        if (!pTargetBase) {
            return false;
        }

        // Write PE headers to target process
        if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, pOldOptHeader->SizeOfHeaders, nullptr)) {
            FreeRemoteMemory(hProc, pTargetBase);
            return false;
        }

        // Write all sections to target process
        auto pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
        for (UINT i = 0; i < pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->SizeOfRawData > 0 &&
                !WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress,
                    pSrcData + pSectionHeader->PointerToRawData,
                    pSectionHeader->SizeOfRawData, nullptr)) {
                FreeRemoteMemory(hProc, pTargetBase);
                return false;
            }
        }

        // Prepare mapping context for shellcode
        MAPPING_CTX data{};
        data.fnLoadLib = LoadLibraryA;
        data.fnGetProc = GetProcAddress;
        data.baseAddr = pTargetBase;
        data.reason = fdwReason;
        data.reserved = lpReserved;
        data.sehEnabled = SEHExceptionSupport;
        data.fnAddTable = (pRtlAddFunctionTable)RtlAddFunctionTable;

        // Allocate and write mapping context to target process
        BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!MappingDataAlloc || !WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(data), nullptr)) {
            FreeRemoteMemory(hProc, pTargetBase);
            FreeRemoteMemory(hProc, MappingDataAlloc);
            return false;
        }

        // Allocate and write shellcode to target process
        void* pShellcode = VirtualAllocEx(hProc, nullptr, SHELLCODE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pShellcode || !WriteProcessMemory(hProc, pShellcode, (void*)Shellcode, SHELLCODE_SIZE, nullptr)) {
            FreeRemoteMemory(hProc, pTargetBase);
            FreeRemoteMemory(hProc, MappingDataAlloc);
            FreeRemoteMemory(hProc, pShellcode);
            return false;
        }

        // Execute shellcode in target process
        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
        if (!hThread) {
            FreeRemoteMemory(hProc, pTargetBase);
            FreeRemoteMemory(hProc, MappingDataAlloc);
            FreeRemoteMemory(hProc, pShellcode);
            return false;
        }

        // Wait for shellcode to complete
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        // Read back the result
        MAPPING_CTX result{};
        if (!ReadProcessMemory(hProc, MappingDataAlloc, &result, sizeof(result), nullptr)) {
            FreeRemoteMemory(hProc, pTargetBase);
            return false;
        }

        if (result.modHandle == INVALID_DATA_POINTER) {
            return false;
        }

        // Clean up shellcode and mapping data
        BYTE zero[SHELLCODE_SIZE] = {};
        WriteProcessMemory(hProc, pShellcode, zero, sizeof(zero), nullptr);
        FreeRemoteMemory(hProc, pShellcode);
        FreeRemoteMemory(hProc, MappingDataAlloc);

        // Wipe PE headers immediately to reduce detection footprint
        BYTE headerZeros[0x1000] = {};  // Wipe first 4KB (typical header size)
        SIZE_T headerSize = min(0x1000, pOldOptHeader->SizeOfHeaders);
        WriteProcessMemory(hProc, pTargetBase, headerZeros, headerSize, nullptr);

        // Track this injection for automatic cleanup
        TrackInjection(hProc, pTargetBase, pOldOptHeader->SizeOfImage, dllName);

        return true;
    }

    // Disable optimizations for shellcode to prevent corruption
    #pragma runtime_checks("", off)
    #pragma optimize("", off)

    void __stdcall Shellcode(MAPPING_CTX* pData) {
        if (!pData) {
            pData->modHandle = INVALID_DATA_POINTER;
            return;
        }

        BYTE* pBase = reinterpret_cast<BYTE*>(pData->baseAddr);
        auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;
        auto _LoadLibraryA = pData->fnLoadLib;
        auto _GetProcAddress = pData->fnGetProc;
        auto _DllMain = reinterpret_cast<BOOL(WINAPI*)(void*, DWORD, void*)>(pBase + pOpt->AddressOfEntryPoint);

        // Handle base relocations if necessary
        BYTE* LocationDelta = pBase - pOpt->ImageBase;
        if (LocationDelta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            const auto* pRelocEnd = reinterpret_cast<BYTE*>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
            
            while (reinterpret_cast<BYTE*>(pRelocData) < pRelocEnd && pRelocData->SizeOfBlock) {
                const UINT Count = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
                
                for (UINT i = 0; i < Count; ++i) {
                    if (RELOC_FLAG(pRelativeInfo[i])) {
                        UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (pRelativeInfo[i] & 0xFFF));
                        *pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
                    }
                }
                pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
            }
        }

        // Process import table
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
            auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            
            while (pImportDesc->Name) {
                HMODULE hMod = _LoadLibraryA(reinterpret_cast<char*>(pBase + pImportDesc->Name));
                if (!hMod) {
                    pData->modHandle = INVALID_DATA_POINTER;
                    return;
                }
                
                ULONG_PTR* pThunk = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
                ULONG_PTR* pFunc = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);
                if (!pThunk) pThunk = pFunc;
                
                for (; *pThunk; ++pThunk, ++pFunc) {
                    if (IMAGE_SNAP_BY_ORDINAL(*pThunk)) {
                        *pFunc = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hMod, reinterpret_cast<char*>(*pThunk & 0xFFFF)));
                    } else {
                        *pFunc = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hMod, reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunk)->Name));
                    }
                }
                ++pImportDesc;
            }
        }

        // Process TLS callbacks
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
            auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
            PIMAGE_TLS_CALLBACK* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
            for (; pCallback && *pCallback; ++pCallback) {
                (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
            }
        }

        // Handle SEH (Structured Exception Handling) for x64
        bool ExceptionSupportFailed = false;
        if (pData->sehEnabled) {
            const auto& excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (excep.Size && !pData->fnAddTable(
                reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
                excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), 
                reinterpret_cast<DWORD64>(pBase))) {
                ExceptionSupportFailed = true;
            }
        }

        // Call DLL entry point
        BOOL dllResult = _DllMain(pBase, pData->reason, pData->reserved);
        pData->modHandle = ExceptionSupportFailed ? SEH_SUPPORT_FAILED : reinterpret_cast<HINSTANCE>(pBase);
    }

    #pragma runtime_checks("", restore)
    #pragma optimize("", on)

    // Simple universal DLL injection function - takes any DLL data
    bool InjectDllData(HANDLE hProcess, BYTE* dllData, size_t dllSize, const char* dllName) {
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE || !dllData || dllSize == 0) {
            return false;
        }
        
        bool result = ManualMapDll(hProcess, dllData, true, DLL_PROCESS_ATTACH, nullptr, dllName ? dllName : "");
        return result;
    }
} // namespace Inject
