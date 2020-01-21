#include "W32Fuzzer.h"
#include "hde32.h"

PVOID PTR_W32_FUNCTION;

// Public ctor
W32Fuzzer::W32Fuzzer(const CHAR* w32ModuleName) {
	this->loadWin32Image(w32ModuleName);
	this->populateExportedFunctions();
	this->RtlRandomEx = (protoRtlRandomEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRandomEx");
}

W32Fuzzer::~W32Fuzzer() {
	for (auto const& fn : this->exportedFunctions) {
		if (fn) {
			VirtualFree(fn, 0, MEM_RELEASE);
		}
	}
}

// Public: returns the image base of the loaded module.
HMODULE W32Fuzzer::getImageBaseAddress() {
	if (!this->imageBaseAddress) {
		return (HMODULE)INVALID_HANDLE_VALUE;
	}

	DWORD dwImageBase = (DWORD)this->imageBaseAddress;

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)dwImageBase;
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
		return (HMODULE)INVALID_HANDLE_VALUE;
	}

	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)(dwImageBase + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE) {
		return (HMODULE)INVALID_HANDLE_VALUE;
	}

	return this->imageBaseAddress;
}

// Public: returns the list of functions exported by name of the currently
// loaded module.
list<PW32_FUNCTION> W32Fuzzer::getExportedFunctions() {
	if (!this->exportedFunctions.empty()) {
		return this->exportedFunctions;
	}

	populateExportedFunctions();
	return this->exportedFunctions;
}

// Public: sets the vectored exception handler used for fuzzing
bool W32Fuzzer::setVectoredHook()
{
	return AddVectoredExceptionHandler(TRUE, W32Fuzzer::VectoredHandler);
}

// Public: removes the vectored exception handler used for fuzzing
bool W32Fuzzer::removeVectoredHook()
{
	return RemoveVectoredExceptionHandler(W32Fuzzer::VectoredHandler);
}

DWORD W32Fuzzer::nextRand()
{
	static DWORD dwSeed = GetTickCount();
	return RtlRandomEx(&dwSeed);
}

void disassembleFunctionArguments(PW32_FUNCTION w32Function) {
	try {
		hde32s s;
		int size = 0;

		do
		{
			size += hde32_disasm((PVOID)((DWORD)w32Function->procAddress + size), &s);
		} while (s.opcode != 0xC2);

		w32Function->argLength = s.imm.imm16 / 4;
	}
	catch (...) {
		DEBUG_BREAK;
	}
}

void W32Fuzzer::test_GetProcLengths() {
	for (auto const& fn : this->exportedFunctions) {
		DWORD dwThreadId;
		PTR_W32_FUNCTION = fn;
		HANDLE hThread = CreateThread(NULL, 0, &W32Fuzzer::ThreadFindParamaterCount, (PVOID)fn, 0, &dwThreadId);
		if (hThread) {
			if (WaitForSingleObject(hThread, 3 * 1000) == WAIT_TIMEOUT) {
				TerminateThread(hThread, -1);
			}
			CloseHandle(hThread);
		}
		if (!fn->exceptionRaised) {
			printf("\tQueried [%s] for [%d] parameters.\n", fn->name, fn->argLength);
		}
	}
}

void W32Fuzzer::test_FuzzAPI_Round1() {
	for (auto const& fn : this->exportedFunctions) {

		if (fn->exceptionRaised) continue;

		printf("Fuzzing [%s] for register artifacts.\n", fn->name);

		// shit way i know, for testing
		/*if (fn->paramBuffer) {
			VirtualFree(fn->paramBuffer, 0, MEM_RELEASE);
		}*/

		fn->paramBuffer = VirtualAlloc(NULL, sizeof(DWORD) * fn->argLength, MEM_COMMIT, PAGE_READWRITE);

		for (size_t i = 0; i < fn->argLength; i++) {
			DWORD badVal = this->nextRand();
			*(DWORD*)fn->paramBuffer = badVal;
			printf("\tParamter [%d] = 0x%08x\n", i, badVal);
		}

		DWORD dwThreadId;
		HANDLE hThread = CreateThread(NULL, 0, &W32Fuzzer::ThreadFuzzFunction, (PVOID)fn, 0, &dwThreadId);
		if (hThread) {
			if (WaitForSingleObject(hThread, 3 * 1000) == WAIT_TIMEOUT) {
				TerminateThread(hThread, -1);
			}
			CloseHandle(hThread);
		}
	}
}

void W32Fuzzer::test_FuzzAPI_Round2()
{
	for (auto const& fn : this->exportedFunctions) {

		if (fn->exceptionRaised) continue;

		printf("Fuzzing [%s] for register artifacts.\n", fn->name);

		//// shit way i know, for testing
		//if (fn->paramBuffer) {
		//	VirtualFree(fn->paramBuffer, 0, MEM_RELEASE);
		//}

		//fn->paramBuffer = VirtualAlloc(NULL, sizeof(DWORD)* fn->argLength, MEM_COMMIT, PAGE_READWRITE);

		//for (size_t i = 0; i < fn->argLength; i++) {
		//	DWORD badVal = this->nextRand();
		//	*(DWORD*)fn->paramBuffer = badVal;
		//	printf("\tParamter [%d] = 0x%08x\n", i, badVal);
		//}

		DWORD dwThreadId;
		HANDLE hThread = CreateThread(NULL, 0, &W32Fuzzer::ThreadFuzzFunction, (PVOID)fn, 0, &dwThreadId);
		if (hThread) {
			if (WaitForSingleObject(hThread, 3 * 1000) == WAIT_TIMEOUT) {
				TerminateThread(hThread, -1);
			}
			CloseHandle(hThread);
		}
		// printf("\Fuzzed [%s] for [%d] parameters.\n", fn->name, fn->argLength);
	}
}

void W32Fuzzer::analyze()
{
	for (auto const& fn : this->exportedFunctions) {

		if (fn->exceptionRaised) continue;

		if ((fn->run1.eax && fn->run2.eax) && (fn->run1.eax == fn->run2.eax)) {
			printf("ARTIFACT FOUND: %s, EAX = 0x%08X\n", fn->name, fn->run1.eax);
			printf("SUB THE MODULE BASE: 0x%08X\n", fn->run1.eax_sub_mod);
		}

		if ((fn->run1.ecx && fn->run2.ecx) && (fn->run1.ecx == fn->run2.ecx)) {
			printf("ARTIFACT FOUND: %s, ECX = 0x%08X\n", fn->name, fn->run1.ecx);
			printf("SUB THE MODULE BASE: 0x%08X\n", fn->run1.ecx_sub_mod);
		}

		if ((fn->run1.edx && fn->run2.edx) && (fn->run1.edx == fn->run2.edx)) {
			printf("ARTIFACT FOUND: %s, EDX = 0x%08X\n", fn->name, fn->run1.edx);
			printf("SUB THE MODULE BASE: 0x%08X\n", fn->run1.edx_sub_mod);
		}

	}
}


// Private: loads the Win32 API library (e.g. gdi32) into memory, if not already
// loaded.
void W32Fuzzer::loadWin32Image(const CHAR* imageName) {
	if (!this->imageBaseAddress) {
		if (!(this->imageBaseAddress = GetModuleHandle(TEXT(imageName)))) {
			if (!(this->imageBaseAddress = LoadLibrary(TEXT(imageName)))) {
				this->imageBaseAddress = (HMODULE)INVALID_HANDLE_VALUE;
			}
		}
	}
}

// Private: populates the list of functions exported by name of the currently
// loaded module.
void W32Fuzzer::populateExportedFunctions() {
	HMODULE imageBase = this->getImageBaseAddress();
	if (!imageBase) {
		return;
	}

	this->exportedFunctions.clear();

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)((DWORD)imageBase);
	PIMAGE_NT_HEADERS pINH =
		(PIMAGE_NT_HEADERS)((DWORD)imageBase + pIDH->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)(
		(DWORD)imageBase +
		pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.VirtualAddress);
	PDWORD pNames = (PDWORD)((DWORD)imageBase + pIED->AddressOfNames);

	for (size_t i = 0; i < pIED->NumberOfNames; i++) {
		CHAR* fnName = (CHAR*)((DWORD)imageBase + pNames[i]);
		WORD fnOrd = ((PWORD)((DWORD)imageBase + pIED->AddressOfNameOrdinals))[i];
		DWORD fnAddr =
			((PDWORD)((DWORD)imageBase + pIED->AddressOfFunctions))[fnOrd];
		PVOID fnProcAddr = (PVOID)((DWORD)imageBase + fnAddr);

		PW32_FUNCTION pFn = (PW32_FUNCTION)VirtualAlloc(NULL, sizeof(W32_FUNCTION), MEM_COMMIT, PAGE_READWRITE);
		lstrcpyA(pFn->name, fnName);

		pFn->procAddress = GetProcAddress(this->imageBaseAddress, fnName);
		pFn->imageBase = (DWORD)this->imageBaseAddress;

		// fn.procAddress = fnProcAddr;

		this->exportedFunctions.push_back(pFn);
	}
}

// Private: thread procedure that will modify the W32_FUNCTION structure passed
// as the parameter, and attempt to find the argument length.
DWORD __stdcall W32Fuzzer::ThreadFindParamaterCount(PVOID lpThreadParams) {

	PW32_FUNCTION fn = (PW32_FUNCTION)lpThreadParams;

	DWORD espRestore;

	__asm {
		mov edx, esp
		mov espRestore, edx
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		push 0
		mov edx, [fn]
		mov eax, [edx + 64] //sizeof(CHAR) * 64
		mov ecx, esp
		mov[edx + 68], ecx
		call eax
		mov edx, [fn]
		mov ecx, esp
		mov[edx + 72], ecx
		mov ecx, [espRestore]
		mov esp, ecx
	}

	fn->argLength = (fn->esp_2 - fn->esp_1) / 4;
}

DWORD __stdcall W32Fuzzer::ThreadFuzzFunction(PVOID lpThreadParams) {

	PW32_FUNCTION fn = (PW32_FUNCTION)lpThreadParams;
	DWORD espRestore;

	DWORD _eax;
	DWORD _ecx;
	DWORD _edx;

	__asm {
		mov edi, esp
		mov espRestore, edi
		mov ebx, [fn]
		mov edx, [ebx + 80]
		xor ecx, ecx
		push_params :
		cmp ecx, dword ptr[ebx + 76]
			je call_function
			push dword ptr[edx + ecx * 4]
			inc ecx
			jmp push_params
			call_function :
		mov esi, [ebx + 64]
			mov ecx, esp
			mov[ebx + 68], ecx
			xor eax, eax
			xor ecx, ecx
			xor edx, edx
			call esi
			mov esp, edi
			mov _eax, eax
			mov _ecx, ecx
			mov _edx, edx
	}

	if (!fn->firstRun) {
		fn->run1.eax = _eax;
		fn->run1.ecx = _ecx;
		fn->run1.edx = _edx;
		//figure out if this is correctly signed subtraction (it's not)
		fn->run1.eax_sub_mod = _eax - fn->imageBase;
		fn->run1.ecx_sub_mod = _ecx - fn->imageBase;
		fn->run1.edx_sub_mod = _edx - fn->imageBase;
		fn->firstRun = 1;
	}
	else {
		fn->run2.eax = _eax;
		fn->run2.ecx = _ecx;
		fn->run2.edx = _edx;
		fn->run2.eax_sub_mod = _eax - fn->imageBase;
		fn->run2.ecx_sub_mod = _ecx - fn->imageBase;
		fn->run2.edx_sub_mod = _edx - fn->imageBase;
	}
}


VOID __stdcall ExitThreadProc() {
	PVOID pExitThreadProc =
		GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), TEXT("ExitThread"));
	__asm {
		push 0
		call pExitThreadProc
	}
}

LONG __stdcall W32Fuzzer::VectoredHandler(_EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID pExitThreadProc =
		GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), TEXT("ExitThread"));

	ExceptionInfo->ContextRecord->Eip = (DWORD)&ExitThreadProc;

	PW32_FUNCTION w32Function = (PW32_FUNCTION)PTR_W32_FUNCTION;
	w32Function->exceptionRaised = true;
	w32Function->exceptionContext = *ExceptionInfo->ContextRecord;

	printf("Could not execute function, will save for 2nd pass (exception): [%s]\n", w32Function->name);

	return EXCEPTION_CONTINUE_EXECUTION;
}
