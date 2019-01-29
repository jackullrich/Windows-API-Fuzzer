#include "W32Fuzzer.h"

int __cdecl main(void) {
	W32Fuzzer* fzUser32 = new W32Fuzzer(TEXT("user32.dll"));

	return 0;
}