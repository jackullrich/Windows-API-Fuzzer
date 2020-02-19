#include "W32Fuzzer.h"

#pragma comment(lib, "crypt32.lib")

int __cdecl main(void) {

	W32Fuzzer* fuzz = new W32Fuzzer("iphlpapi.dll");

	DWORD _ecx = 0;

	CertAlgIdToOID(0x38589451);
	__asm {
		mov _ecx, ecx
		int 3
	}

	auto functions = fuzz->getExportedFunctions();
	auto imagebase = fuzz->getImageBaseAddress();

	fuzz->setTimeout(500);
	fuzz->setVectoredHook();
	fuzz->test_GetProcLengths();
	fuzz->test_FuzzAPI_Round1();
	fuzz->test_FuzzAPI_Round2();
	fuzz->analyze();
	fuzz->removeVectoredHook();

	DEBUG_BREAK;

	return 0;
}