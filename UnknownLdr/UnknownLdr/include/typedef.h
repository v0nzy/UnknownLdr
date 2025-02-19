#pragma once

#include <Windows.h>

typedef HANDLE(WINAPI* fnOpenProcess)(
	DWORD							dwDesiredAccess,
	BOOL							bInheritHandle,
	DWORD							dwProcessId
	);

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
	);
