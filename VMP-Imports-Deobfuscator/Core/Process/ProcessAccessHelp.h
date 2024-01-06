#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <vector>

// @note: @colby57: This file is not changed.

// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS (200)

/************************************************************************/

class ApiInfo;

class ModuleInfo
{
public:

	WCHAR fullPath[MAX_PATH];
	DWORD_PTR modBaseAddr;
	DWORD modBaseSize;

	bool isAlreadyParsed;
	bool parsing;

	/*
	  for iat rebuilding with duplicate entries:

	  ntdll = low priority
	  kernelbase = low priority
	  SHLWAPI = low priority

	  kernel32 = high priority
	  
	  priority = 1 -> normal/high priority
	  priority = 0 -> low priority
	*/
	int priority;

	std::vector<ApiInfo *> apiList;

	ModuleInfo()
	{
		modBaseAddr = 0;
		modBaseSize = 0;
		priority = 1;
		isAlreadyParsed = false;
		parsing = false;
	}

	const WCHAR * getFilename() const
	{
		const WCHAR* slash = wcsrchr(fullPath, L'\\');
		if(slash)
		{
			return slash+1;
		}
		return fullPath;
	}
};

class ApiInfo
{
public:
	char name[MAX_PATH];
	WORD hint;
	DWORD_PTR va;
	DWORD_PTR rva;
	WORD ordinal;
	bool isForwarded;
	ModuleInfo * module;
};

namespace ProcessAccessHelp
{
	inline HANDLE hProcess{};

	inline DWORD_PTR targetImageBase{};
	inline DWORD_PTR targetSizeOfImage{};
	inline DWORD_PTR maxValidAddress{};

	inline ModuleInfo * selectedModule;

	inline std::vector<ModuleInfo> moduleList; //target process module list
	inline std::vector<ModuleInfo> ownModuleList; //own module list

	inline const size_t PE_HEADER_BYTES_COUNT = 2000;

	inline BYTE fileHeaderFromDisk[PE_HEADER_BYTES_COUNT];

	bool openProcessHandle(DWORD dwPID);
	HANDLE NativeOpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId);
	void closeProcessHandle();

	bool getProcessModules(HANDLE hProcess, std::vector<ModuleInfo> &moduleList);

	LPVOID createFileMappingViewRead(const WCHAR * filePath);
	LPVOID createFileMappingViewFull(const WCHAR * filePath);

	LPVOID createFileMappingView(const WCHAR * filePath, DWORD accessFile, DWORD flProtect, DWORD accessMap);

	bool readMemoryFromProcess(DWORD_PTR address, SIZE_T size, LPVOID dataBuffer);
	bool writeMemoryToProcess(DWORD_PTR address, SIZE_T size, LPVOID dataBuffer);

	bool readMemoryPartlyFromProcess(DWORD_PTR address, SIZE_T size, LPVOID dataBuffer);
	bool readMemoryFromFile(HANDLE hFile, LONG offset, DWORD size, LPVOID dataBuffer);
	bool writeMemoryToFile(HANDLE hFile, LONG offset, DWORD size, LPCVOID dataBuffer);
	bool writeMemoryToNewFile(const WCHAR * file,DWORD size, LPCVOID dataBuffer);


	DWORD getProcessByName(const WCHAR * processName);
	bool getMemoryRegionFromAddress(DWORD_PTR address, DWORD_PTR * memoryRegionBase, SIZE_T * memoryRegionSize);

	SIZE_T getSizeOfImageProcess(HANDLE processHandle, DWORD_PTR moduleBase);
	bool getSizeOfImageCurrentProcess();

	LONGLONG getFileSize(HANDLE hFile);
	LONGLONG getFileSize(const WCHAR * filePath);

	bool createBackupFile(const WCHAR * filePath);

	DWORD getModuleHandlesFromProcess(const HANDLE hProcess, HMODULE ** hMods );

	void setCurrentProcessAsTarget();

	bool suspendProcess();
	bool resumeProcess();
	bool terminateProcess();
    bool isPageExecutable( DWORD Protect );
	bool isPageAccessable( DWORD Protect );
    SIZE_T getSizeOfImageProcessNative( HANDLE processHandle, DWORD_PTR moduleBase );
}
