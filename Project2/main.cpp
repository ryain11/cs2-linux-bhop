#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include "ManualMapInjection.h"

#include <fstream>
#include <string>
#include <iostream>
#include <vector>

const char* GetWorkingDir() {
	static char buffer[MAX_PATH]{};

	DWORD len = GetCurrentDirectoryA(MAX_PATH, buffer);

	if (len == 0) return nullptr;

	return buffer;
}

DWORD GetProcessIdByName(const wchar_t* processName)
{
	DWORD processId = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W entry;
	entry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (_wcsicmp(entry.szExeFile, processName) == 0) {
				processId = entry.th32ProcessID;
				break;
			}
		} while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return processId;
}

int main() {
	const wchar_t* pName = L"cs2.exe";
	DWORD pid = GetProcessIdByName(pName);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	const char* currentDir = GetWorkingDir();
	std::string dllpath = std::string(currentDir) + "\\cs2_bhop.dll";

	std::ifstream file(dllpath, std::ios::binary | std::ios::ate);
	size_t fileSize = file.tellg();
	file.seekg(0);

	std::vector<BYTE> dllData(fileSize);
	file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
	file.close();

	// Inject the DLL
	if (Inject::InjectDllData(hProcess, dllData.data(), dllData.size(), "YourDll.dll")) {
		std::cout << "Injection successful!" << std::endl;
	}
	else {
		std::cerr << "Injection failed!" << std::endl;
	}

	// Cleanup when done
	Inject::PerformCleanup();

	CloseHandle(hProcess);

	return 0;
}