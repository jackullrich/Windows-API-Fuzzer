#pragma once

#include <list>

#include <Windows.h>

using namespace std;

typedef struct _W32_FUNCTION {
	CHAR name[64];
	PVOID procAddress;
	DWORD esp_1;
	DWORD esp_2;
	DWORD argLength;
} W32_FUNCTION, *PW32_FUNCTION;

class W32Fuzzer
{
public:
	W32Fuzzer(CHAR* w32ModuleName);
	~W32Fuzzer();

	HMODULE getImageBaseAddress();
	list<W32_FUNCTION> getExportedFunctions();

	void test_GetProcLengths();

private:
	void loadWin32Image(CHAR* imageName);
	void populateExportedFunctions();

	static DWORD WINAPI argLengthProc(PVOID lpThreadParams);

	HMODULE imageBaseAddress;
	list<W32_FUNCTION> exportedFunctions;
};