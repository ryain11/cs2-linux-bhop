#include "headers/cs2_bhop.h"
#include <sys/mman.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>
#include "headers/funchook.h"
#include <vector>
#include "headers/offsets.h"
#include "headers/fifo.h"

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

static int fifo_fd = -1;
static volatile Flags flags;

void init_fifo() {
    fifo_fd = open(FIFO_PATH, O_RDONLY | O_NONBLOCK);
    return;
}

int returnPawnAddr(void* self, uint32_t slot, long active, long extra) { 

    localPlayerPawn = reinterpret_cast<uintptr_t>(getPlayerPawn(slot));
    
    return 1;
}

void hkCreateMove(void* self, uint64_t slot, long cmd) {
    if (!flags.bhopEnabled) return;

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

    // 3. Get player's current health and flags
    int32_t health = *reinterpret_cast<int32_t*>(localPlayerPawn + offsets::iHealth);
    uint32_t flags  = *reinterpret_cast<uint32_t*>(localPlayerPawn + offsets::fFlags);

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

    bool jumpRequested = (*pButtonState1 & IN_JUMP) || (*pButtonState2 & IN_JUMP);

    if (jumpRequested) {
        if (!isOnGround) {
            *pButtonState1 &= ~IN_JUMP;
            *pButtonState2 &= ~IN_JUMP;
        } 
    } 
    
}

// --- Hook Setup ---
void* SetupHook(void* arg) {
    const char* bytePattern = "55 89 f7 48 89 e5 41 55 49 89 cd 41 54 49 89 d4 53 48 83 ec 08 e8 ? ? ? ?";
    const char* realCreateMove = "55 48 89 E5 41 57 49 89 D7 41 56 49 89 FE 41 55 41 54 53 89 F3 48 81 EC ? ? ? ? 48 89 BD ? ? ? ? 48 89 95 ? ? ? ? E8 ? ? ? ? 4C 89 FA 89 DE 4C 89 F7";
    const char* playerPawnPattern = "55 48 89 E5 83 FF FF 75 ? 48 8D 05 ? ? ? ? 48 8B 38 48 8B 07 FF 90 10 03 00 00";

    auto mod = get_module_info("libclient.so");
    if (!mod) return NULL;

    uintptr_t function_address = FindPatternInModule("libclient.so", realCreateMove);
    if (function_address == 0) return NULL;

    uintptr_t pawn_lookup_addr = FindPatternInModule("libclient.so", playerPawnPattern);
    if (pawn_lookup_addr == 0) return NULL;

    uintptr_t pawn_actual_addr = FindPatternInModule("libclient.so", bytePattern);
    if (pawn_actual_addr == 0) return NULL;

    funchook_t *funchook = funchook_create();
    if (!funchook) return NULL;

    // Assign the target address to oCreateMove (funchook rewrites this to point to the original execution trampoline)
    PawnHelper = reinterpret_cast<PawnHelperFn>(pawn_actual_addr);
    getPlayerPawn = reinterpret_cast<FindPawnFn>(pawn_lookup_addr);
    oCreateMove = reinterpret_cast<CreateMoveFn>(function_address);

    // Prepare hook: (handle, target_func_ptr_ref, detour_func_ptr)
    int rv = funchook_prepare(funchook, reinterpret_cast<void**>(&oCreateMove), reinterpret_cast<void*>(hkCreateMove));
    int rv2 = funchook_prepare(funchook, reinterpret_cast<void**>(&PawnHelper), reinterpret_cast<void*>(returnPawnAddr));
    if (rv2 != FUNCHOOK_ERROR_SUCCESS || rv != FUNCHOOK_ERROR_SUCCESS) {
        goto cleanup;
    }

    // Install trampoline & write inline jump instructions
    rv = funchook_install(funchook, 0);
    if (rv != FUNCHOOK_ERROR_SUCCESS) {
        goto cleanup;
    }

    init_fifo();

    while (!flags.uninject) {
        if (fifo_fd < 0) {
            init_fifo();
            usleep(5000);
            continue;
        }
        else {
            Flags incoming;
            if (read(fifo_fd, reinterpret_cast<void*>(&incoming), sizeof(Flags)) > 0) {
                flags.bhopEnabled = incoming.bhopEnabled;
                flags.uninject = incoming.uninject;
                usleep(5000);
            }
        }
    }

    funchook_uninstall(funchook, 0);
    cleanup:
    funchook_destroy(funchook);
    close(fifo_fd);

    return NULL;
}

static pthread_t thread_id;
__attribute__((constructor))
void on_attach() {
    
    // Spawns worker_thread so on_attach can return safely
    pthread_create(&thread_id, NULL, SetupHook, NULL);
}

__attribute__((destructor))
void on_detach() {
    flags.uninject = true;
    if (thread_id) {
        pthread_join(thread_id, NULL);
    }

    usleep(50000);
}