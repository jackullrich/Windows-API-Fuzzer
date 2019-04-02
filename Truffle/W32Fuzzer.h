#pragma once

#include <list>

#include <Windows.h>

using namespace std;

#define DEBUG_BREAK __asm { int 3 }

// idea:
// fuzz with (1<--->16 parameters pointing to a piece of RWE shellcode 
// the shellcode should have an int 3 which will trigger a breakpoint to know successful

typedef struct _W32_FUNCTION_EXECUTION_STATE {
	// stdcall - Registers EAX, ECX, and EDX are designated for use within the function.
	DWORD eax;
	DWORD ecx;
	DWORD edx;
	// can also perform a deep scan and compare everything
	CONTEXT ctx;
} W32_FUNCTION_EXECUTION_STATE, *PW32_FUNCTION_EXECUTION_STATE;

// TODO: Classify parameter typing (e.g. DATA_VALUE, DATA_REFERENCE, CODE_REFERENCE, etc...
typedef struct _W32_FUNCTION {
	
	CHAR name[64];
	PVOID procAddress;
	
	DWORD esp_1;
	DWORD esp_2;
	DWORD argLength;
	
	// All i could think of at the time was to make a buffer with n= argLength * sizeof(DWORD) and fill randomly 
	// then push each reading sizeof(DWORD) at a time
	PVOID paramBuffer;

	W32_FUNCTION_EXECUTION_STATE pre;
	W32_FUNCTION_EXECUTION_STATE post;
	
} W32_FUNCTION, *PW32_FUNCTION;

class W32Fuzzer
{
public:
	W32Fuzzer(const CHAR* w32ModuleName);
	~W32Fuzzer();

	HMODULE getImageBaseAddress();
	list<PW32_FUNCTION> getExportedFunctions();
	bool setVectoredHook();
	bool removeVectoredHook();

	void test_GetProcLengths();

	void test_FuzzAPI_Round1();

private:
	void loadWin32Image(const CHAR* imageName);
	void populateExportedFunctions();

	static DWORD __stdcall ThreadFindParamaterCount(PVOID lpThreadParams);
	static DWORD __stdcall ThreadFuzzFunction(PVOID lpThreadParams);
	static LONG	 __stdcall VectoredHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);

	HMODULE imageBaseAddress;
	list<PW32_FUNCTION> exportedFunctions;
};