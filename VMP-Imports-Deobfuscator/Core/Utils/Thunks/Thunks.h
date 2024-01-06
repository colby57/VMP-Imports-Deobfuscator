#pragma once

#include <windows.h>
#include <map>

// @note: @colby57: This file is not changed.

class ImportThunk
{
public:
	WCHAR moduleName[MAX_PATH];
	char name[MAX_PATH];
	DWORD_PTR va;
	DWORD_PTR rva;
	WORD ordinal;
	DWORD_PTR apiAddressVA;
	WORD hint;
	bool valid;
	bool suspect;

	DWORD_PTR key;
};

class ImportModuleThunk
{
public:
	WCHAR moduleName[MAX_PATH];
	std::map<DWORD_PTR, ImportThunk> thunkList;

	DWORD_PTR firstThunk;
	DWORD_PTR key;
};
