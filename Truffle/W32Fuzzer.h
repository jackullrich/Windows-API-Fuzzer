#pragma once

#include <list>

#include <Windows.h>

using namespace std;

#define DEBUG_BREAK __asm { int 3 }

typedef struct _W32_FUNCTION {
	TCHAR name[64];
	PVOID procAddress;
	DWORD esp_1;
	DWORD esp_2;
	DWORD argLength;
} W32_FUNCTION, *PW32_FUNCTION;

class W32Fuzzer
{
public:
	W32Fuzzer(const TCHAR* w32ModuleName);
	~W32Fuzzer();

	HMODULE getImageBaseAddress();
	list<W32_FUNCTION> getExportedFunctions();
	bool setVectoredHook();
	bool removeVectoredHook();

	void test_GetProcLengths();

private:
	void loadWin32Image(const TCHAR* imageName);
	void populateExportedFunctions();

	static DWORD WINAPI ThreadFindParamaterCount(PVOID lpThreadParams);
	static LONG WINAPI VectoredHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);

	HMODULE imageBaseAddress;
	list<W32_FUNCTION> exportedFunctions;
};