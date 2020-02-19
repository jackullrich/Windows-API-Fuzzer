#include <Windows.h>

char eicar[] = "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#pragma comment(lib, "crypt32.lib")

int main(void) {

	DWORD dwWritten = 0;
	HANDLE hFile = 0;

	DWORD _ecx = 0;

	//CertAlgIdToOID(0x38589451);
	//__asm {
	//	mov _ecx, ecx
	//}

	//if (_ecx != 4) {
	//	return 1;
	//}

	hFile = CreateFile(TEXT("eicar.com.txt"), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if (!hFile) {
		return 0;
	}

	if (!WriteFile(hFile, eicar, sizeof(eicar), &dwWritten, NULL)) {
		CloseHandle(hFile);
		return 0;
	}

	CloseHandle(hFile);
	return 1;
}