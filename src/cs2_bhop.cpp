#include "headers/cs2_bhop.h"
#include <sys/mman.h>
#include "headers/funchook.h"
#include <vector>
#include "headers/gui.h"

#define IN_JUMP (1ULL << 1)

// m_fFlags bitmask on LocalPlayerPawn
#define FL_ONGROUND (1 << 0)

// --- Detour Function ---
using PawnHelperFn = int(*)(void* self, uint32_t slot, long active, long extra);
static PawnHelperFn PawnHelper = nullptr;

using CreateMoveFn = void(*)(void* self, uint64_t slot, long cmd);
static CreateMoveFn oCreateMove = nullptr;

using FindPawnFn = void*(*)(int pawn);
static FindPawnFn getPlayerPawn = nullptr;

uintptr_t localPlayerPawn = 0;


int returnPawnAddr(void* self, uint32_t slot, long active, long extra) { 

    localPlayerPawn = reinterpret_cast<uintptr_t>(getPlayerPawn(slot));
    
    return 1;
}

void hkCreateMove(void* self, uint64_t slot, long cmd) {

    if (oCreateMove) {
        oCreateMove(self, slot, cmd);
    }

    static auto mod = get_module_info("libclient.so");
    static uintptr_t base_address = mod->base;

    if (base_address == 0) {
        return;
    }

    if (localPlayerPawn == 0) {
        return;
    }

    uintptr_t f_flags_offset = 0x564;
    uintptr_t i_health_offset = 0x4BC;

    // 3. Get player's current health and flags
    int32_t health = *reinterpret_cast<int32_t*>(localPlayerPawn + i_health_offset);
    uint32_t flags  = *reinterpret_cast<uint32_t*>(localPlayerPawn + f_flags_offset);

    // Ensure player is alive
    if (health <= 0) {
        return;
    }
    
    bool isOnGround = (flags & FL_ONGROUND) != 0;

    uintptr_t cUserCmd = static_cast<uintptr_t>(cmd);
    if (cUserCmd == 0) return;

    uintptr_t pInButtonState = (cUserCmd + 0x58);
    if (pInButtonState == 0) return;
    
    uint64_t* pButtonState1 = reinterpret_cast<uint64_t*>(pInButtonState + 0x08);
    uint64_t* pButtonState2 = reinterpret_cast<uint64_t*>(pInButtonState + 0x10);

    uintptr_t CsgoUserCmdPB = (cUserCmd + 0x18);
    if (CsgoUserCmdPB == 0) return;

    uintptr_t pBaseCmd = *reinterpret_cast<uintptr_t*>(CsgoUserCmdPB + 0x28);
    if (pBaseCmd == 0) return;

    uintptr_t InButtonStatePB = *reinterpret_cast<uintptr_t*>(pBaseCmd + 0x34);
    if (InButtonStatePB == 0) return;

    uintptr_t pButStatePB1 = (InButtonStatePB + 0x08);
    uintptr_t pButStatePB2 = (InButtonStatePB + 0x10);

    float subtickJump = ((*reinterpret_cast<uintptr_t*>(pBaseCmd + 0x24)) + 0x24);


    bool jumpRequested = (*pButtonState1 & IN_JUMP) || (*pButtonState2 & IN_JUMP);


    if (jumpRequested && bhopEnabled) {
        if (!isOnGround) { 
            subtickJump = 0.0f;
            *pButtonState1 &= ~IN_JUMP;
            pButStatePB1 &= ~IN_JUMP;
            *pButtonState2 &= ~IN_JUMP;
            pButStatePB2 &= ~IN_JUMP;
        } 
    } 
    
}

// --- Hook Setup ---
void* SetupHook(void* arg) {
    const char* bytePattern = "55 89 f7 48 89 e5 41 55 49 89 cd 41 54 49 89 d4 53 48 83 ec 08 e8 ? ? ? ?";
    const char* realCreateMove = "55 48 89 E5 41 57 49 89 D7 41 56 49 89 FE 41 55 41 54 53 89 F3 48 81 EC ? ? ? ? 48 89 BD ? ? ? ? 48 89 95 ? ? ? ? E8 ? ? ? ? 4C 89 FA 89 DE 4C 89 F7";
    const char* playerPawnPattern = "55 48 89 E5 83 FF FF 75 ? 48 8D 05 ? ? ? ? 48 8B 38 48 8B 07 FF 90 10 03 00 00";

    auto mod = get_module_info("libclient.so");
    if (!mod) {
        return nullptr;
    }

    pid_t pid = getpid();
    uintptr_t function_address = FindPatternInModule("libclient.so", realCreateMove);
    if (function_address == 0) {
        return nullptr;
    }

    uintptr_t pawn_lookup_addr = FindPatternInModule("libclient.so", playerPawnPattern);
    if (pawn_lookup_addr == 0) {
        return nullptr;
    }

    uintptr_t pawn_actual_addr = FindPatternInModule("libclient.so", bytePattern);
    if (pawn_actual_addr == 0) {
        return nullptr;
    }

    funchook_t *funchook = funchook_create();
    if (!funchook) {
        return nullptr;
    }

    // Assign the target address to oCreateMove (funchook rewrites this to point to the original execution trampoline)
    PawnHelper = reinterpret_cast<PawnHelperFn>(pawn_actual_addr);
    getPlayerPawn = reinterpret_cast<FindPawnFn>(pawn_lookup_addr);
    oCreateMove = reinterpret_cast<CreateMoveFn>(function_address);

    // Prepare hook: (handle, target_func_ptr_ref, detour_func_ptr)
    int rv = funchook_prepare(funchook, reinterpret_cast<void**>(&oCreateMove), reinterpret_cast<void*>(hkCreateMove));
    if (rv != FUNCHOOK_ERROR_SUCCESS) {
        funchook_destroy(funchook);
        return nullptr;
    }

    int rv2 = funchook_prepare(funchook, reinterpret_cast<void**>(&PawnHelper), reinterpret_cast<void*>(returnPawnAddr));
    if (rv2 != FUNCHOOK_ERROR_SUCCESS) {
        funchook_destroy(funchook);
        return nullptr;
    }

    // Install trampoline & write inline jump instructions
    rv = funchook_install(funchook, 0);
    if (rv != FUNCHOOK_ERROR_SUCCESS) {
        funchook_destroy(funchook);
        return nullptr;
    }

    while (!uninject) sleep(5);

    funchook_destroy(funchook);

    return nullptr;
}

__attribute__((constructor))
void on_attach() {
    pthread_t thread1_id, thread2_id;
    // Spawns worker_thread so on_attach can return safely
    pthread_create(&thread1_id, NULL, SetupHook, NULL);
    pthread_detach(thread1_id);

    pthread_create(&thread2_id, NULL, drawGui, NULL);
    pthread_detach(thread2_id);
}