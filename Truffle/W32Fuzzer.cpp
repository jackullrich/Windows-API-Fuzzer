#include "W32Fuzzer.h"

// Public ctor
W32Fuzzer::W32Fuzzer(const CHAR* w32ModuleName) {
	this->loadWin32Image(w32ModuleName);
	this->populateExportedFunctions();
}

W32Fuzzer::~W32Fuzzer() {
	for (auto const& fn : this->exportedFunctions) {
		VirtualFree(fn, 0, MEM_RELEASE);
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

void W32Fuzzer::test_GetProcLengths() {
	for (auto const& fn : this->exportedFunctions) {
		printf("Querying [%s] for parameter count.\n", fn->name);
		//DEBUG_BREAK;
		DWORD dwThreadId;
		HANDLE hThread = CreateThread(NULL, 0, &W32Fuzzer::ThreadFindParamaterCount, (PVOID)fn, 0, &dwThreadId);
		if (hThread) {
			if (WaitForSingleObject(hThread, 30 * 1000) == WAIT_TIMEOUT) {
				TerminateThread(hThread, -1);
			}
			CloseHandle(hThread);
		}
		printf("\tQueried [%s] for [%d] parameters.\n", fn->name, fn->argLength);
	}
}

void W32Fuzzer::test_FuzzAPI_Round1() {
	for (auto const& fn : this->exportedFunctions) {
		printf("Fuzzing [%s] for register artifacts.\n", fn->name);

		// shit way i know, for testing
		if (fn->paramBuffer) {
			VirtualFree(fn->paramBuffer, 0, MEM_RELEASE);
		}

		fn->paramBuffer = VirtualAlloc(NULL, sizeof(DWORD)* fn->argLength, MEM_COMMIT, PAGE_READWRITE);

		for (size_t i = 0; i < fn->argLength; i++) {
			DWORD badVal = GetTickCount();
			*(DWORD*)fn->paramBuffer = badVal;
			printf("\tParamter [%d] = 0x%08x\n", i, badVal);
			Sleep(50);
		}

		DWORD dwThreadId;
		HANDLE hThread = CreateThread(NULL, 0, &W32Fuzzer::ThreadFuzzFunction, (PVOID)fn, 0, &dwThreadId);
		if (hThread) {
			if (WaitForSingleObject(hThread, 30 * 1000) == WAIT_TIMEOUT) {
				TerminateThread(hThread, -1);
			}
			CloseHandle(hThread);
		}
		// printf("\Fuzzed [%s] for [%d] parameters.\n", fn->name, fn->argLength);
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

	__asm {
		mov edx, esp
		mov espRestore, edx
		mov ebx, [fn]
		// mov ecx, [ebx + 76] // ecx=#args
		mov edx, [ebx + 80] // ebx=paramBuffer
		xor ecx, ecx
		push_params :
		cmp ecx, dword ptr[ebx + 76]
			je call_function
			push dword ptr[edx + ecx * 4]
			inc ecx
			jmp push_params
			call_function :
		mov eax, [ebx + 64]
			mov ecx, esp
			mov[ebx + 68], ecx
			call eax
			int 3
			pushad
	}
}

LONG __stdcall W32Fuzzer::VectoredHandler(_EXCEPTION_POINTERS * ExceptionInfo)
{
	PVOID pExitThreadProc =
		GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), TEXT("ExitThread"));
	ExceptionInfo->ContextRecord->Eip = (DWORD)pExitThreadProc;
	// DEBUG_BREAK;
	return EXCEPTION_CONTINUE_EXECUTION;
}
