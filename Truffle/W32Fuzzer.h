#pragma once

#include <list>

#include <Windows.h>

using namespace std;

#define DEBUG_BREAK __asm { int 3 }

typedef ULONG(__stdcall *protoRtlRandomEx) (PULONG Seed);

// maybe idea:
// fuzz with (1<--->16 parameters pointing to a piece of RWE shellcode 
// the shellcode should have an int 3 which will trigger a breakpoint to know successful

// maybe idea:
// protect each instruction PAGE_GUARD then single step through the function 
// somehow hash this into a unique value and use as emulation

typedef struct _W32_FUNCTION_EXECUTION_STATE {
	// stdcall - Registers EAX, ECX, and EDX are designated for use within the function.
	DWORD eax;
	DWORD ecx;
	DWORD edx;

	LONGLONG eax_sub_mod;
	LONGLONG ecx_sub_mod;
	LONGLONG edx_sub_mod;
	// can also perform a deep scan and compare everything
	// CONTEXT ctx;
} W32_FUNCTION_EXECUTION_STATE, *PW32_FUNCTION_EXECUTION_STATE;

// TODO: Classify parameter typing (e.g. DATA_VALUE, DATA_REFERENCE, CODE_REFERENCE, etc...)
typedef struct _W32_FUNCTION {

	CHAR name[64];
	PVOID procAddress;

	DWORD esp_1;
	DWORD esp_2;
	DWORD argLength;

	// All i could think of at the time was to make a buffer with n= argLength * sizeof(DWORD) and fill randomly 
	// then push each reading sizeof(DWORD) at a time
	PVOID paramBuffer;

	W32_FUNCTION_EXECUTION_STATE run1;
	W32_FUNCTION_EXECUTION_STATE run2;

	DWORD imageBase;

	BOOLEAN firstRun;

	BOOLEAN exceptionRaised;
	CONTEXT exceptionContext;

	DWORD imageSize;

} W32_FUNCTION, *PW32_FUNCTION;


class W32Fuzzer
{
public:
	W32Fuzzer(const CHAR* w32ModuleName);
	~W32Fuzzer();

	HMODULE getImageBaseAddress();
	DWORD getSizeOfImage();
	list<PW32_FUNCTION> getExportedFunctions();
	bool SetVectoredHook();
	bool removeVectoredHook();
	void GetProcLengths();
	void FuzzAPI_Round1();
	void FuzzAPI_Round2();
	void Analyze();
	void SetTimeout(DWORD dwMilliSec);

private:
	void loadWin32Image(const CHAR* imageName);
	void populateExportedFunctions();

	DWORD nextRand();

	static DWORD __stdcall ThreadFindParamaterCount(PVOID lpThreadParams);
	static DWORD __stdcall ThreadFuzzFunction(PVOID lpThreadParams);
	static LONG	 __stdcall VectoredHandler(struct _EXCEPTION_POINTERS *ExceptionInfo);

	HMODULE imageBaseAddress;
	list<PW32_FUNCTION> exportedFunctions;
	protoRtlRandomEx RtlRandomEx;
	DWORD timeout;
};