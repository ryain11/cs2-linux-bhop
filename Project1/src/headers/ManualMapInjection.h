#pragma once
#include <Windows.h>
#include <string>
#include <cstddef>

// Mapping context structure passed to shellcode
typedef struct _MAPPING_CTX {
    LPVOID baseAddr;                    // Base address where DLL is mapped
    HINSTANCE(WINAPI* fnLoadLib)(LPCSTR);     // Pointer to LoadLibraryA
    FARPROC(WINAPI* fnGetProc)(HMODULE, LPCSTR); // Pointer to GetProcAddress
    HINSTANCE modHandle;                // Result handle after mapping
    DWORD reason;                       // DLL entry reason (DLL_PROCESS_ATTACH, etc.)
    LPVOID reserved;                    // Reserved parameter for DllMain
    BOOL sehEnabled;                    // Whether SEH support is enabled
    BOOL(WINAPI* fnAddTable)(PVOID, DWORD, DWORD64); // RtlAddFunctionTable for SEH
} MAPPING_CTX, * PMAPPING_CTX;

// Function pointer type for RtlAddFunctionTable
typedef BOOL(WINAPI* pRtlAddFunctionTable)(
    PVOID FunctionTable,
    DWORD EntryCount,
    DWORD64 BaseAddress
);

namespace Inject {
    /**
     * @brief Shellcode executed in target process to perform manual mapping
     * @param pData Pointer to MAPPING_CTX structure containing mapping information
     * 
     * This function is copied to the target process and executes the following:
     * 1. Applies base relocations
     * 2. Resolves imports
     * 3. Executes TLS callbacks
     * 4. Registers SEH handlers (if enabled)
     * 5. Calls DllMain
     */
    void __stdcall Shellcode(MAPPING_CTX* pData);

    /**
     * @brief Manually maps a DLL into a target process
     * @param hProc Handle to target process (requires PROCESS_ALL_ACCESS)
     * @param pSrcData Pointer to DLL data in memory
     * @param SEHExceptionSupport Enable structured exception handling support (x64)
     * @param fdwReason Reason code for DllMain (typically DLL_PROCESS_ATTACH)
     * @param lpReserved Reserved parameter for DllMain
     * @param dllName Name of DLL for tracking purposes (optional)
     * @return true on success, false on failure
     * 
     * This function:
     * - Allocates memory at a random base address in the target process
     * - Writes PE sections to the allocated memory
     * - Executes shellcode to complete the mapping process
     * - Wipes PE headers for stealth
     * - Tracks the injection for later cleanup
     */
    bool ManualMapDll(
        HANDLE hProc,
        BYTE* pSrcData,
        bool SEHExceptionSupport,
        DWORD fdwReason,
        LPVOID lpReserved,
        const std::string& dllName
    );

    /**
     * @brief High-level DLL injection function
     * @param hProcess Handle to target process
     * @param dllData Pointer to DLL file data
     * @param dllSize Size of DLL data in bytes
     * @param dllName Optional name for tracking (can be nullptr)
     * @return true on success, false on failure
     * 
     * Simplified interface for injecting a DLL. Automatically enables SEH support
     * and uses DLL_PROCESS_ATTACH as the entry reason.
     */
    bool InjectDllData(
        HANDLE hProcess,
        BYTE* dllData,
        size_t dllSize,
        const char* dllName
    );

    /**
     * @brief Cleans up all tracked DLL injections
     * 
     * For each tracked injection:
     * 1. Wipes the memory content (zeros out the original PE size)
     * 2. Frees the allocated memory region
     * 3. Removes from tracking list
     * 
     * Call this before your injector exits to avoid leaving traces.
     */
    void PerformCleanup();

    /**
     * @brief Gets the number of currently tracked injections
     * @return Number of active injections being tracked
     */
    size_t GetTrackedInjectionCount();

    /**
     * @brief Stops tracking injections without freeing memory
     * 
     * Use this if you want to leave DLLs injected but stop managing them.
     * The injected DLLs will remain in the target process until it exits.
     */
    void CleanupInjectionTracking();
}
