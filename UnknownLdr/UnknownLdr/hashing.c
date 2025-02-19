#include <Windows.h>

#include "include/typedef.h"
#include "include/common.h"
#include "include/debug.h"
#include "include/structs.h"

// We define the encryption algorithm (Jenkins One At A Time), and set a seed for randomization
#define INITIAL_SEED	7

// Set macros for the memset function to make the binary CRT independent
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	// logic similar to memset's one
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}

HANDLE OpenProc(DWORD dwProcessId) {

	// Load KERNEL32.DLL
	LoadLibraryA("KERNEL32.DLL");

	// Get handle to KERNEL32.DLL
	HMODULE hKernel32Module = GetModuleHandleH(KERNEL32DLL_HASH);

	// Using handle to get the address of OpenProcess
	fnOpenProcess pOpenProcess = (fnOpenProcess)GetProcAddressH(hKernel32Module, OPENPROCESS_HASH);

	// Open handle to the remote process
	HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess == NULL) {
		PRINTA("[ERROR] OpenProcess Failed With Error: %d\n", GetLastError());
		return -1;
	}
	return hProcess;
}


UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// Macros to make it easier to hash
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

// We hash the custom GetProcAddressReplacement function (This is a loop which compares the hash of the function we're looking for, in this case the hash of User32.dll)
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	// We do this to avoid casting each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;

	// Get the DOS header
	PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;

	// Get the NT header
	PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);

	// Get the optional header
	IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Get the image export table
	PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	// Loop to find the base address of the USER32.DLL function
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// hashing every function name `pFunctionName`
		// if both hashes are equal, then we found the function we want 
		if (dwApiNameHash == HASHA(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
}

// Creating the custom GetModuleHandleH function which gets the PEB via TEB intrensic function and loops the hash value of MessageBox
HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {

	// Get pointer to PEB via offset 0x60 TEB
	PPEB pPeb = (PEB*)(__readgsqword(0x60));

	// Get the Ldr from PEB
	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

	// Get the first element of the linked list
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	// While loop to find the base address of the MessageBoxA function
	while (pDte) {
		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {
			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)_ToUpper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			if (HASHA(UpperCaseDllName) == dwModuleNameHash)
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
		}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}