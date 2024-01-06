#pragma once

#include "Core/Process/ProcessAccessHelp.h"
#include "Core/ApiReader/ApiReader.h"

#include <iostream>
#include <set>
#include <stdio.h>
#include <wchar.h>
#include <vector>
#include <inttypes.h>
#include <algorithm>

namespace VMPCore
{
	enum eCallIatMode
	{
		CALL_IAT_UNKNOWN = 0,
		CALL_IAT_COMMON,
		CALL_IAT_JMP,
		CALL_IAT_MOV_REG
	};

	enum eIatEncryptMode
	{
		IAT_ENCRYPT_UNKNOWN,
		IAT_ENCRYPT_CALL_RET,
		IAT_ENCRYPT_PUSH_CALL
	};

	struct S_IatPatchInfo
	{
		int m_iCallIatMode{};
		int m_iIatEncryptMode{};
		int m_iRegIndex{};

		std::uintptr_t m_pPatchAddress{};
		std::uintptr_t m_pBaseModule{};
		std::uintptr_t m_pApiAddress{};
		std::uintptr_t m_pIatAddress{};

		char m_szApi[256] = { 0 };
	};

	inline std::vector<std::uintptr_t> vecPatternAddressList{};
	inline std::uintptr_t pCurrentPatternAddress{};

	inline ApiReader sApiReader{};

	inline std::vector<std::uintptr_t> vecModuleList{};
	inline std::map<std::uintptr_t, std::set<std::uintptr_t>> mapImportEchmoduleApi{};

	inline std::uintptr_t pIatAddress{};
	inline std::size_t k32IatSize{};

	inline std::uintptr_t pImageLoadAddress{};
	inline std::uintptr_t pImageBaseAddress{};
	inline std::size_t k32ImageSize{};

	inline std::uintptr_t pImageBuffer{};

	inline std::vector<S_IatPatchInfo> vecPatchInfo{};

	inline bool bUseIatSection = false;

	inline std::vector<IMAGE_SECTION_HEADER> vecProcessSections{};

	void ParseModules();
	void GetModulePathByAddress(std::uintptr_t Address, ModuleInfo& sTargetModule);
	void ParseApiList();

	bool SetPatchIatAddress();
	void ApplyPatches();

	bool RebuildIAT();
	bool PatchCalls();
}



