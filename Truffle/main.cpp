#include "W32Fuzzer.h"

int __cdecl main(void) {

	W32Fuzzer* fzNCrypt = new W32Fuzzer("ncrypt.dll");
	//test
	auto functions = fzNCrypt->getExportedFunctions();
	auto imagebase = fzNCrypt->getImageBaseAddress();

	fzNCrypt->setVectoredHook();
	fzNCrypt->test_GetProcLengths();
	fzNCrypt->test_FuzzAPI_Round1();
	fzNCrypt->removeVectoredHook();

	DEBUG_BREAK;

	return 0;
}