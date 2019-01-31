#include "W32Fuzzer.h"

int __cdecl main(void) {

	W32Fuzzer* fzUser32 = new W32Fuzzer(TEXT("user32.dll"));

	auto functions = fzUser32->getExportedFunctions();
	auto imagebase = fzUser32->getImageBaseAddress();

	fzUser32->setVectoredHook();

	fzUser32->test_GetProcLengths();
	
	fzUser32->removeVectoredHook();

	DEBUG_BREAK;

	return 0;
}