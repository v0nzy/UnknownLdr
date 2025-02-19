#include <Windows.h>

#include "include/common.h"

// Replace CRT functions
CHAR _ToUpper(CHAR c) {
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 'A';
    }
    return c;
}

// Replace the srand/rand function
ULONG RandomSeed;

void SetPseudoRandomSeed(ULONG Seed) {
    RandomSeed = Seed;
}

INT GetPseudoRandomInteger() {
    return PseudoRandomIntegerSubroutine(&RandomSeed);
}

INT PseudoRandomIntegerSubroutine(PULONG Context) {
    return ((*Context = *Context * 1103515245 + 12345) % ((ULONG)RAND_MAX + 1));
}

INT CreatePseudoRandomInteger(_In_ ULONG Seed) {
    return PseudoRandomIntegerSubroutine(&Seed);
}

