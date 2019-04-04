#include "W32Fuzzer.h"

int __cdecl main(void) {

	W32Fuzzer* fzNCrypt = new W32Fuzzer("netapi32.dll");

	auto functions = fzNCrypt->getExportedFunctions();
	auto imagebase = fzNCrypt->getImageBaseAddress();

	fzNCrypt->setVectoredHook();
	fzNCrypt->test_GetProcLengths();
	fzNCrypt->test_FuzzAPI_Round1();
	fzNCrypt->test_FuzzAPI_Round2();
	fzNCrypt->removeVectoredHook();

	DEBUG_BREAK;

	return 0;
}