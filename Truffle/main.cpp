#include "W32Fuzzer.h"

#pragma comment(lib, "crypt32.lib")

int __cdecl main(void) {

	W32Fuzzer* fzNCrypt = new W32Fuzzer("crypt32.dll");


	DWORD _ecx = 0;

	CertAlgIdToOID(0x38589451);
	__asm {
		mov _ecx, ecx
		int 3
	}

	auto functions = fzNCrypt->getExportedFunctions();
	auto imagebase = fzNCrypt->getImageBaseAddress();

	fzNCrypt->setVectoredHook();
	fzNCrypt->test_GetProcLengths();
	fzNCrypt->test_FuzzAPI_Round1();
	fzNCrypt->test_FuzzAPI_Round2();
	fzNCrypt->analyze();
	fzNCrypt->removeVectoredHook();

	DEBUG_BREAK;

	return 0;
}