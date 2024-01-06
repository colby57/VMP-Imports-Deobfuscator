#pragma once

#include <unicorn/unicorn.h>
#include <iostream>
#include <stdio.h>
#include <vector>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include <windows.h>

#include "../ApiReader/ApiReader.h"
#include "../../VMPCore.h"

namespace Emulator
{
	constexpr auto ExecuteInstructionMax = 0x40000;
	constexpr auto StackAddress = 0x0;
	constexpr auto StackSize = 1024 * 1024;
	constexpr auto StackInitValue = 0xFF;

	const static uc_x86_reg eReg64Table[] =
	{ 
		UC_X86_REG_RAX, 
		UC_X86_REG_RCX, 
		UC_X86_REG_RDX,
		UC_X86_REG_RBX,
		UC_X86_REG_RSP,
		UC_X86_REG_RBP,
		UC_X86_REG_RSI,
		UC_X86_REG_RDI,
		UC_X86_REG_R8,
		UC_X86_REG_R9,
		UC_X86_REG_R10,
		UC_X86_REG_R11,
		UC_X86_REG_R12,
		UC_X86_REG_R13,
		UC_X86_REG_R14,
		UC_X86_REG_R15 
	};

	inline uc_engine* Unicorn;
	inline uc_context* UnicornContext;

	inline uc_hook UnicornHookTrace{};

	inline void* StackBuffer;
	inline int EmulatorNum{};

	const bool IsInstructionRet(const std::uint8_t Opcode);
	const bool IsInstructionRetn(const std::uint8_t Opcode[]);

	int GetMovRegIndex(std::uintptr_t& RegisterIndexBuffer);
	const int GetPushPopRegIndex();

	bool IsApiValid(std::unordered_map<DWORD_PTR, ApiInfo*>::iterator& ApiInfoIterator, std::uintptr_t Address);
	bool CheckCurrentEmulateStatus(std::uint64_t Address);

	static void TraceCallback(uc_engine* Unicorn, uint64_t Address, uint32_t Size, void* UserData);

	void Start(std::uintptr_t patternAddress);
	bool Init(void* PeBuffer);
}