#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

#define DLL_NAME "mydll.dll"
#define PROC_NAME L"notepad.exe"

DWORD GetProcessID(const wchar_t* procname);

int main()
{
	char* buffer = new char;

	// Get full path of DLL to inject
	DWORD pathLen = GetFullPathNameA(
		DLL_NAME,
		MAX_PATH,
		buffer,
		NULL
	);

	std::cout << buffer << std::endl;

	if (!pathLen)
	{
		delete buffer;
		std::cerr << "GetFullPathNameA() Failed" << std::endl;
		return 0;
	}

	// Get LoadLibrary function address –
	// the address doesn't change at remote process

	// Since the handle could be null
	HMODULE kernelHandle = GetModuleHandleA("kernel32.dll");
	if (!kernelHandle)
	{
		std::cerr << "GetModuleHandleA() Failed" << std::endl;
		auto error = GetLastError();
		return -1;
	}

	FARPROC addrLoadLibrary = GetProcAddress(kernelHandle, "LoadLibraryA");
	if (!addrLoadLibrary)
	{
		delete buffer;
		std::cerr << "GetProcAddress() Failed" << std::endl;
		return 0;
	}

	// Getting the PID
	DWORD notepadId = 0;
	do {
		notepadId = GetProcessID(PROC_NAME);
		Sleep(1000);
	} while (!notepadId);
	// Open remote process
	HANDLE proc = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		notepadId
	);

	if (!proc)
	{
		delete buffer;
		std::cerr << "OpenProcess() Failed" << std::endl;
		return 0;
	}

	// Get a pointer to memory location in remote process,
	// big enough to store DLL path
	PVOID memAddr = (PVOID)VirtualAllocEx(
		proc,
		NULL,
		pathLen,
		MEM_COMMIT,
		PAGE_READWRITE
	);
	if (!memAddr) {
		delete buffer;
		std::cerr << "VirtualAllocEx() Failed" << std::endl;
		auto err = GetLastError();
		return 0;
	}

	// Write DLL name to remote process memory
	BOOL check = WriteProcessMemory(
		proc,
		memAddr,
		buffer,
		pathLen,
		NULL
	);
	if (!check) {
		delete buffer;
		std::cerr << "WriteProcessMemory() Failed" << std::endl;
		auto err = GetLastError();
		return 0;
	}

	// Open remote thread, while executing LoadLibrary
	// with parameter DLL name, will trigger DLLMain
	HANDLE hRemote = CreateRemoteThread(
		proc,
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)addrLoadLibrary,
		memAddr,
		NULL,
		NULL
	);

	if (!hRemote) {
		std::cerr << "CreateRemoteThread() Failed" << std::endl;
		VirtualFreeEx(proc, memAddr, NULL, MEM_RELEASE);
		CloseHandle(proc);
		delete buffer;
		auto err = GetLastError();
		return 0;
	}

	std::cout << "Done!";

	VirtualFreeEx(proc, memAddr, NULL, MEM_RELEASE);
	CloseHandle(proc);
	WaitForSingleObject(hRemote, INFINITE);
	check = CloseHandle(hRemote);
	delete buffer;
	return 0;
}

DWORD GetProcessID(const wchar_t* procname)
{
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return pid;  // Failed to create snapshot, return 0
	}

	PROCESSENTRY32 process;
	process.dwSize = sizeof(process);
	if (!Process32First(hSnap, &process)) {
		CloseHandle(hSnap);
		return pid;  // Failed to get first process, return 0
	}

	do {
		if (_wcsicmp(process.szExeFile, procname) == 0) {
			pid = process.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnap, &process));

	CloseHandle(hSnap);
	return pid;
}