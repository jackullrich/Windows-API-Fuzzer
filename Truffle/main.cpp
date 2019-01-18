#include <Windows.h>
#include <winnt.h>
#include <winternl.h>

#define DEBUG_BREAK __asm { int 3 }

LONG WINAPI
VectoredHandler(
	struct _EXCEPTION_POINTERS *ExceptionInfo
)
{
	PVOID pExitThreadProc = GetProcAddress(GetModuleHandle("kernel32.dll"), "ExitThread");
	ExceptionInfo->ContextRecord->Eip = (DWORD)pExitThreadProc;

	DEBUG_BREAK;

	return EXCEPTION_CONTINUE_EXECUTION;
}

typedef struct _API_FUNCTION {
	CHAR name[64];
	PVOID proc_address;
	DWORD esp_1;
	DWORD esp_2;
	DWORD arg_length;
} API_FUNCTION, *PAPI_FUNCTION;

// should probably compile in __stdcall for all functions
DWORD WINAPI fuzz_proc(PVOID params) {

	PAPI_FUNCTION api = (PAPI_FUNCTION)params;

	DWORD esp_save = 0;

	__asm {
		mov ecx, esp
		mov esp_save, ecx

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

		mov edx, [api]
		mov eax, [edx + 64]
		mov ecx, esp
		mov[edx + 68], ecx

		DEBUG_BREAK
		call eax

		mov edx, [api]
		mov ecx, esp
		mov[edx + 72], ecx
		DEBUG_BREAK

		mov ecx, [esp_save]
		mov esp, ecx
	}

	api->arg_length = (api->esp_2 - api->esp_1) / 4;
	DEBUG_BREAK;
}

int main() {

	AddVectoredExceptionHandler(TRUE, VectoredHandler);

	HMODULE hUser32 = LoadLibrary("user32.dll");
	if (!hUser32) {
		DEBUG_BREAK;
	}

	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)hUser32;
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
		DEBUG_BREAK;
	}

	PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((DWORD)hUser32 + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE) {
		DEBUG_BREAK;
	}

	DWORD iedRVA = pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	IMAGE_EXPORT_DIRECTORY *pIED = (IMAGE_EXPORT_DIRECTORY *)((DWORD)hUser32 + iedRVA);
	DWORD *nameRVAs = (DWORD *)((DWORD)hUser32 + pIED->AddressOfNames);
	for (DWORD i = 0; i < pIED->NumberOfNames; ++i) {
		char *functionName = (char *)((DWORD)hUser32 + nameRVAs[i]);
		WORD ordinal = ((WORD *)((DWORD)hUser32 + pIED->AddressOfNameOrdinals))[i];
		DWORD functionRVA = ((DWORD *)((DWORD)hUser32 + pIED->AddressOfFunctions))[ordinal];
		PVOID pProcAddress = (PVOID)((DWORD)hUser32 + functionRVA);

		PAPI_FUNCTION api = (PAPI_FUNCTION)VirtualAlloc(NULL, sizeof(PAPI_FUNCTION), MEM_COMMIT, PAGE_READWRITE);
		lstrcpy(api->name, functionName);
		api->proc_address = pProcAddress;

		DWORD thread_id;
		HANDLE hFuzzThread = CreateThread(NULL, 0, fuzz_proc, (PVOID)api, 0, &thread_id);
		if (hFuzzThread) {
			if (WaitForSingleObject(hFuzzThread, 20 * 1000) == WAIT_TIMEOUT) {
				TerminateThread(hFuzzThread, -1);
			}
			CloseHandle(hFuzzThread);
		}

	}

	RemoveVectoredExceptionHandler(VectoredHandler);
}