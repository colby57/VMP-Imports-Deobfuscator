#pragma once

#include <Zydis/Zydis.h>
#include <windows.h>
#include <iostream>
#include <cstdint>

struct S_DisasmWrapper
{
	std::uintptr_t m_pRuntimeAddr{};

	ZydisDecodedInstruction m_sInstruction{};
	ZydisDecodedOperand m_sOperands[ZYDIS_MAX_OPERAND_COUNT]{};
};

namespace ZydisWrapper
{
	ZyanUSize AssembleCall(ZyanU8* Buffer, ZyanUSize BufferLength, int CallIatMode, std::uintptr_t IatAddress, std::uintptr_t PatchAddress, int RegIndex);
	void AppendInstruction(const ZydisEncoderRequest* pEncoderRequest, ZyanU8** Buffer, ZyanUSize* BufferLength);
	
	bool Disasm(S_DisasmWrapper& sDisasm, std::uintptr_t Data, int Length);
	std::uintptr_t CalculateAbsoluteAddr(S_DisasmWrapper& sDisasm, std::size_t nOperandSize);
}