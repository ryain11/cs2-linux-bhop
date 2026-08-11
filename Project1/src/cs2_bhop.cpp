#define no_init_all
#include "headers/cs2_bhop.h"
#include "headers/offsets.hpp"
#include "minhook/include/MinHook.h"
#include "headers/gui.h"

#define FL_ONGROUND (1 << 0)
#define IN_JUMP (1ULL << 1)

static HMODULE clientBase = GetModuleHandleW(L"client.dll");

using CreateMoveFn = void(*)(LONGLONG self, uint32_t slot, LONGLONG cmd);
static CreateMoveFn oCreateMove = nullptr;

void hkCreateMove(LONGLONG self, uint32_t slot, LONGLONG cmd) {
	if (oCreateMove) {
		oCreateMove(self, slot, cmd);
	}
	uintptr_t playerPawnOffset = cs2_dumper::offsets::client_dll::dwLocalPlayerPawn;

	uintptr_t localPlayerPawn = *reinterpret_cast<uintptr_t*>(clientBase + playerPawnOffset);

	if (localPlayerPawn == 0) return;

	uintptr_t iHealthOffset = 0x34C;
	uintptr_t fFlagsOffset = 0x3F4;

	int32_t health = *reinterpret_cast<int32_t*>(localPlayerPawn + iHealthOffset);
	uint32_t flags = *reinterpret_cast<uint32_t*>(localPlayerPawn + fFlagsOffset);

	if (health <= 0) return;

	bool isOnGround = (flags & FL_ONGROUND) != 0;

	uintptr_t cUserCmd = static_cast<uintptr_t>(cmd);
	if (cUserCmd == 0) return;

	uintptr_t pInButtonState = (cUserCmd + 0x58);
	if (pInButtonState == 0) return;

	int64_t* pButtonState1 = reinterpret_cast<int64_t*>(pInButtonState + 0x08);
	int64_t* pButtonState2 = reinterpret_cast<int64_t*>(pInButtonState + 0x10);

	bool jumpRequested = (*pButtonState1 & IN_JUMP);

	if (jumpRequested && bhopEnabled && !isOnGround) {
		*pButtonState2 &= ~IN_JUMP;
		*pButtonState1 &= ~IN_JUMP;
	}
}

DWORD WINAPI Setup(LPVOID instance) {
	const char* cMovePattern = "48 8B C4 4C 89 40 18 48 89 48 08 55 53 41 54 41 55 48 8D A8 ?? ?? ?? ?? 48 81 EC 08 02 00 00";

	uintptr_t crMoveAddr = patternScan(clientBase, cMovePattern);

	oCreateMove = reinterpret_cast<CreateMoveFn>(crMoveAddr);

	MH_Initialize();

	MH_CreateHook(
		reinterpret_cast<LPVOID>(crMoveAddr),
		reinterpret_cast<LPVOID>(&hkCreateMove),
		reinterpret_cast<LPVOID*>(&oCreateMove)
	);

	MH_EnableHook(MH_ALL_HOOKS);

	while (!uninject) {
		Sleep(5);
	}

	MH_DisableHook(MH_ALL_HOOKS);
	MH_RemoveHook(MH_ALL_HOOKS);
	MH_Uninitialize();

	FreeLibraryAndExitThread(static_cast<HMODULE>(instance), 0);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(instance);

		const HANDLE thread = CreateThread(
			nullptr,
			NULL,
			Setup,
			instance,
			NULL,
			nullptr
		);

		if (thread) CloseHandle(instance);

		return TRUE;
	}
}